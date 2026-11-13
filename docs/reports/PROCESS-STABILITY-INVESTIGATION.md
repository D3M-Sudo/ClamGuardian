# ClamGuardian — Process Stability Investigation

**Date:** 2026-11-13  
**Repository:** `D3M-Sudo/ClamGuardian`  
**Base:** `feature` @ `16792cdf797720eef08c39e71c3016b6161fd3f8`  
**Investigation branch:** `investigation/process-stability`  
**Pull request:** [#43 — Draft](https://github.com/D3M-Sudo/ClamGuardian/pull/43)  
**Scope:** Diagnostic tests and source-level characterization only. No production code or shared workflow files were changed.

## 1. Executive summary

The investigation confirmed four material subprocess behaviors:

1. FreshClam progress output does not reset the configured command timeout. The current implementation uses an absolute timeout.
2. CLI subprocess stdout and stderr are merged, then fully captured by `communicate()`. There is no application-level output-size bound in this path.
3. A clamd timeout, socket error, or protocol/value error is caught by `scan()` and followed by a clamscan fallback. Explicit task cancellation is propagated and does not trigger that fallback.
4. Process-group SIGTERM can terminate the direct child while leaving a descendant that ignores SIGTERM alive. The current termination helper waits for the direct child and can return before the descendant is gone.

The investigation also verified that cancellation while waiting for the scan-runner concurrency slot does not consume the slot, and that stopping the scheduler propagates cancellation to an active scan.

No production remediation was performed. Findings below are inputs to Phase 1.

## 2. Evidence and CI

### GitHub Actions

| Workflow | Run | Result | Evidence |
|---|---:|---|---|
| CI | [#514 / 43359503193](https://github.com/D3M-Sudo/ClamGuardian/actions/runs/43359503193) | **Success** | All test, lint, type-check, dependency-audit, and packaging jobs succeeded |
| Release Gate | [#457 / 43359503339](https://github.com/D3M-Sudo/ClamGuardian/actions/runs/43359503339) | **Success** | Preflight, AppStream, real ClamAV, GTK smoke, and local Flatpak jobs succeeded; release-manifest job was skipped as expected for a PR |

### Test matrix

| Runtime | Full suite | Diagnostic tests |
|---|---:|---:|
| Python 3.11 | 625 passed, 9 skipped | 9 passed |
| Python 3.12 | 625 passed, 9 skipped | 9 passed |
| Python 3.13 | 625 passed, 9 skipped | 9 passed |
| Python 3.14 headless runtime | 595 passed, 22 skipped | 9 passed |

The skip counts differ because the Python 3.14 job uses the headless `[test]` extra, while the 3.11–3.13 matrix installs `[test,gtk]` and the GTK system dependencies.

The 3.11–3.13 jobs also passed Ruff and mypy. The pinned dependency audit passed. Native Flatpak packaging passed on x86_64 and aarch64; native AppImage packaging passed on x86_64 and aarch64.

The Release Gate additionally passed its real ClamAV checks (clamscan and clamd), AppStream validation, GTK smoke test, and local GNOME 51 Flatpak build. This is GitHub-hosted CI evidence, not a substitute for validation on the user's desktop host.

### CI correction during investigation

The first diagnostic commit failed Ruff because its process cleanup used a try/except/pass pattern flagged by SIM105. The cleanup was changed to `contextlib.suppress(ProcessLookupError)` in a test-only commit. The final CI run on the current branch head passed Ruff, mypy, and all tests.

## 3. Confirmed findings

### PS-01 — FreshClam uses an absolute command timeout

**Status:** Confirmed by source inspection and deterministic test.

- Source: `clamguardian/engines/clamav.py`, `update_signatures()` and `_run_command()` (approximately lines 568–703).
- `ClamAVEngine.command_timeout` defaults to 300 seconds.
- `_run_command()` wraps `process.communicate()` in `asyncio.wait_for(..., command_timeout)`.
- Output activity is not observed or used to refresh the timeout.
- Diagnostic test: `test_freshclam_progress_does_not_reset_absolute_command_timeout`.
- The fake FreshClam executable continuously emitted progress but still timed out at the configured deadline.

**Implication for Phase 1:** Separate an inactivity timeout from a maximum execution timeout. Refresh the inactivity deadline on observed stdout/stderr activity, while retaining a separately configurable hard upper bound.

### PS-02 — CLI output is merged and fully buffered

**Status:** Confirmed by source inspection and deterministic test.

- Source: `clamguardian/engines/clamav.py`, `_run_command()` (approximately lines 682–703).
- stdout is `PIPE`; stderr is redirected to stdout.
- `communicate()` reads the complete output and returns it as a bytes object.
- No application-level byte cap, rolling buffer, or progressive parser is applied to this CLI output path.
- Diagnostic test: `test_cli_command_captures_large_combined_output_in_full`.
- The test emitted 2 MiB to stdout and 2 MiB to stderr and verified that all 4 MiB were returned together.

**Implication for Phase 1:** Drain stdout and stderr continuously, parse incrementally, bound retained diagnostic output, preserve detections, and expose truncation explicitly. Reaching a retention limit must not stop pipe draining; otherwise a child can block on a full pipe.

### PS-03 — clamd failures can trigger a second CLI scan

**Status:** Confirmed by source inspection and deterministic tests.

- Source: `clamguardian/engines/clamav.py`, `scan()` (approximately lines 162–175).
- The clamd path is wrapped in `asyncio.wait_for(..., command_timeout)`.
- `TimeoutError`, `OSError`, and `ValueError` are caught together, after which `_run_cli_scan()` is invoked.
- Diagnostic tests:
  - `test_clamd_failure_falls_back_to_clamscan[timeout]`
  - `test_clamd_failure_falls_back_to_clamscan[socket_error]`
  - `test_clamd_failure_falls_back_to_clamscan[protocol_error]`
- All three cases invoked the CLI fallback exactly once.
- `test_cancelling_clamd_scan_does_not_start_cli_fallback` verified that external task cancellation propagates as `CancelledError` and does not invoke clamscan.

**Implication for Phase 1:** Make fallback policy reason-specific. A missing/refused/unavailable socket can reasonably select clamscan. A timeout should be considered separately: automatically starting a second scan can repeat expensive work and obscure the original timeout. Whether a protocol/value error should fall back or fail explicitly should be decided as a documented policy. Preserve the existing cancellation distinction.

**Limit:** These tests prove that the client invokes the CLI after a clamd timeout. They do not prove whether a real clamd server continues scanning after its client connection is cancelled; that server-side behavior was not measured.

### PS-04 — A surviving descendant can outlive process termination

**Status:** Confirmed by deterministic Linux process test and source inspection.

- Source: `clamguardian/engines/clamav.py`, `_terminate_process()` (approximately lines 707–733).
- The helper sends SIGTERM to the process group, then waits on the direct `Process` object.
- SIGKILL escalation occurs only if waiting for the direct process itself reaches the grace timeout.
- Diagnostic test: `test_process_group_termination_can_leave_sigterm_ignoring_descendant`.
- The test starts a parent and a child in the same new session. The child ignores SIGTERM. After `_terminate_process()` returns and the parent has been reaped, the test observes the descendant still active.
- The test always SIGKILLs the descendant during cleanup to prevent a leaked process on the CI runner.

**Implication for Phase 1:** Process-group shutdown must account for descendants independently of the direct child's exit. A parent exiting promptly must not cause cleanup to stop while a member of its process group remains alive. Preserve a bounded grace period and ensure escalation targets the original process group safely. Add regression tests for parent-exits-first, child-ignores-SIGTERM, and process-tree cleanup.

### PS-05 — Runner and scheduler cancellation paths behaved correctly in tested cases

**Status:** Confirmed by deterministic tests and existing suite.

- Runner source: `clamguardian/core/runner.py`, semaphore acquisition in `submit()` and task cancellation in `cancel_all()`.
- Scheduler source: `clamguardian/core/scheduler.py`, `start()`, `stop()`, and `_scheduler_loop()`.
- Diagnostic test: `test_cancelled_runner_waiter_does_not_leak_concurrency_slot`.
- Diagnostic test: `test_scheduler_stop_cancels_in_flight_scan`.
- Both passed in all four Python runtime jobs.
- Existing descriptor-worker tests in `tests/test_realtime.py` also cover cancellation interrupting a socket worker, timeout tracking until descriptor cleanup, worker-capacity reservation, and atomic worker limits. The full suite passed those tests.

**Conclusion:** No runner/scheduler production change is justified by the current evidence. Keep these tests as regression coverage while changing subprocess lifecycle behavior in Phase 1.

## 4. Additional source-level observation

### Partial output on cancellation

**Status:** Source-level observation; no dedicated partial-output retention test was added in this investigation.

When `_run_command()` is cancelled while awaiting `communicate()`, it terminates the process and re-raises `CancelledError`. The method does not return the output already emitted, and the scan caller does not receive a partial `ScanResult`.

This is distinct from the confirmed clamd fallback behavior. Phase 1 should explicitly decide whether partial detections are retained for diagnostics or whether cancellation intentionally discards the incomplete scan result. Do not silently mark an incomplete scan as clean.

## 5. Diagnostic test inventory

File: `tests/test_process_stability_diagnostics.py`

1. `test_freshclam_progress_does_not_reset_absolute_command_timeout`
2. `test_cli_command_captures_large_combined_output_in_full`
3. `test_clamd_failure_falls_back_to_clamscan[timeout]`
4. `test_clamd_failure_falls_back_to_clamscan[socket_error]`
5. `test_clamd_failure_falls_back_to_clamscan[protocol_error]`
6. `test_cancelling_clamd_scan_does_not_start_cli_fallback`
7. `test_process_group_termination_can_leave_sigterm_ignoring_descendant`
8. `test_cancelled_runner_waiter_does_not_leak_concurrency_slot`
9. `test_scheduler_stop_cancels_in_flight_scan`

All nine passed on Python 3.11, 3.12, 3.13, and the Python 3.14 headless runtime.

## 6. Phase 1 recommendations

Recommended implementation order remains:

1. **BM-03 — clamd fallback policy:** distinguish unavailable socket from timeout, protocol failure, and cancellation; prevent an unintended second scan on timeout unless explicitly justified.
2. **BM-01 — FreshClam timeout model:** implement inactivity timeout plus an independent maximum execution timeout.
3. **BM-02 — bounded progressive output:** concurrently drain streams, parse detections incrementally, cap retained output, and preserve truncation/partial-result metadata.
4. **BM-04 — process lifecycle and cancellation:** ensure descendant cleanup, bounded SIGTERM/SIGKILL escalation, output drain, and deterministic reaping.

Keep BM-05 scheduler backend, BM-06 profiles, BM-07/08 history and quarantine, BM-09 battery policy, and BM-10 Nemo integration out of this subprocess remediation sequence. Current scheduler/runner cancellation tests passed; revisit them only if the subprocess changes expose a regression.

## 7. Limitations and deferred validation

- CI uses GitHub-hosted Linux runners. It does not reproduce every Linux Mint desktop, Flatpak host-spawn configuration, filesystem, process supervisor, or ClamAV daemon deployment.
- The Release Gate's real ClamAV and clamd tests passed on its ephemeral runner, not on the user's host.
- Memory use was not profiled at process level. The 4 MiB capture test establishes complete buffering without a configured cap, not a measured peak-RSS value.
- No very-long-duration FreshClam update was run; the timeout behavior was reproduced with a short deterministic deadline and continuous output.
- No production code was changed, and no host-level service, socket, USB, or desktop integration was altered.

## 8. Final investigation verdict

**The subprocess stability investigation has sufficient reproducible evidence to proceed to Phase 1 design/implementation planning.** The strongest confirmed remediation targets are the absolute FreshClam timeout, fully buffered CLI output, broad clamd fallback after timeout, and descendant process survival after parent exit.

The runner and scheduler cancellation paths passed their targeted tests and should be preserved. The PR remains Draft and is not ready for review or merge by authorization.
