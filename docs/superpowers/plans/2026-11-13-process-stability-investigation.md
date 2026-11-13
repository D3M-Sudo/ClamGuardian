# Process Stability Investigation Plan

> **For agentic workers:** Execute this plan task-by-task. Each task is restricted to the isolated `investigation/process-stability` branch.

**Original goal:** Produce reproducible, CI-backed evidence about ClamGuardian subprocess, timeout, output, cancellation, fallback, and scheduling behavior without changing production code. This original investigation was completed before the separately authorized Phase 1 amendment below.

**Original architecture:** Characterize the existing implementation through isolated diagnostic tests and deterministic child-process fixtures. Record confirmed behavior, failures, and limitations in a technical report.

**Tech Stack:** Python 3.11+, asyncio, pytest, pytest-asyncio, GitHub Actions.

**Spec:** User-approved scope in the ClamGuardian process-stability investigation conversation.

## Global Constraints

- Base branch: `feature`; investigation branch: `investigation/process-stability`.
- All commits and files remain on `investigation/process-stability`.
- The original investigation tasks below were read-only with respect to production code.
- The separately authorized Phase 1 amendment permits scoped changes to `clamguardian/engines/clamav.py`, regression tests, `CHANGELOG.md`, and the investigation report only.
- No shared workflow changes, production-host actions, or protected-branch changes.
- Do not modify shared workflow configuration or any branch other than `investigation/process-stability`.
- Open a Draft PR targeting `feature`; never mark ready, approve, close, or merge it.
- Use GitHub Actions triggered by the Draft PR to test the investigation head; report any trigger limitations.

## Review Focus

- Continuous output resets the inactivity deadline, but cannot extend the independent maximum execution deadline.
- stdout and stderr are drained concurrently; retained output and separately preserved detection records remain bounded.
- Late detections beyond the ordinary output cap remain visible, with truncation explicitly recorded.
- clamd fallback occurs only for missing/refused socket connections; timeout, protocol/transport errors and cancellation do not start clamscan.
- A timeout remains TIMEOUT and retains partial detections; cancellation remains CancelledError and carries bounded partial diagnostics.
- Process-group cleanup terminates SIGTERM-resistant descendants even after the direct session leader exits, while promptly reaping the parent when no descendants remain.
- Cancellation while waiting for runner capacity does not leak a slot, and scheduler shutdown still cancels an active scan.


## Phase 1 implementation amendment — authorized 2026-11-13

The user explicitly authorized implementation on the existing `investigation/process-stability` branch, retaining PR #43 as Draft. This amendment supersedes the original production-code prohibition only for the bounded scope below.

### Binding defaults and policy

| Parameter / policy | Approved value |
|---|---:|
| Command inactivity timeout | 600 seconds |
| Maximum command execution time | 3600 seconds |
| Ordinary output retention | 1 MiB |
| SIGTERM grace period | 5 seconds |
| clamd fallback after missing/refused socket | Allowed |
| clamd fallback after timeout | Forbidden |
| clamd fallback after protocol/value or unrelated socket error | Forbidden |
| Fallback after cancellation | Forbidden |

Timeout values and output cap are constructor-configurable. No new runtime dependency is authorized or required.

### Implementation tasks

1. **BM-03 — fallback classification**
   - Restrict fallback to missing/refused socket connection.
   - Return TIMEOUT/ERROR for incomplete or invalid clamd attempts without starting clamscan.
   - Preserve cancellation propagation.
2. **BM-01 — timeout semantics**
   - Drain output while tracking last activity.
   - Reset inactivity deadline on actual stdout/stderr progress.
   - Enforce independent maximum execution deadline.
3. **BM-02 — bounded progressive output**
   - Drain stdout and stderr concurrently.
   - Bound ordinary retained output and separately bound parsed detection records.
   - Preserve late detections and explicit truncation metadata.
4. **BM-04 — process lifecycle**
   - Signal the process group even if the direct session leader has exited.
   - Escalate SIGTERM to SIGKILL after the approved grace period.
   - Reap the direct child and drain pipes.
   - Preserve bounded partial diagnostics on timeout and cancellation; never map incomplete work to CLEAN.
5. **Delivery evidence**
   - Add regression tests for each behavior.
   - Update `CHANGELOG.md` and this report.
   - Run CI and Release Gate on the current PR head.
   - Perform a read-only whole-branch review and use AI Delivery Evidence Checker.
   - Keep PR #43 Draft; no approval, Ready for Review, or merge without further explicit authorization.

---

### Task 1: Baseline and source mapping

**Files:**
- Read: `clamguardian/engines/clamav.py`
- Read: `clamguardian/core/runner.py`
- Read: `clamguardian/core/scheduler.py`
- Read: `tests/test_engine.py`
- Read: `tests/test_cancellation.py`
- Read: `tests/test_runner_enrichment.py`
- Read: `tests/test_scheduler.py`
- Read: `.github/workflows/ci.yml`

- [ ] Record the exact base SHA and verify the investigation branch initially matches it.
- [ ] Map current timeout, output, clamd fallback, cancellation, process-group, runner, and scheduler paths.
- [ ] Inventory existing coverage to avoid duplicating already-proven behavior.

### Task 2: Diagnostic characterization tests

**Files:**
- Create: `tests/test_process_stability_diagnostics.py`

- [ ] Add a deterministic fake FreshClam executable that emits progress while running longer than `command_timeout`; assert whether the current timeout is absolute.
- [ ] Add a bounded-size high-output child-process test that records whether stdout and stderr are merged and fully buffered by `communicate()`.
- [ ] Add a clamd timeout characterization test that observes whether `scan()` invokes the clamscan fallback.
- [ ] Add a cancellation characterization test proving cancellation is not converted into a clamscan fallback.
- [ ] Add a parent/descendant process-group test where the descendant ignores SIGTERM; ensure the test cleans up any surviving child even when the observed behavior is defective.
- [ ] Add runner/scheduler cancellation and concurrency tests only where existing tests do not already establish the behavior.
- [ ] Run focused diagnostic tests and existing cancellation/engine/runner/scheduler tests in CI.

### Task 3: CI and evidence collection

**Files:**
- Read: `.github/workflows/ci.yml`
- No workflow modifications.

- [ ] Open the PR as Draft from `investigation/process-stability` to `feature`.
- [ ] Confirm CI runs against the investigation head only.
- [ ] Inspect all job results and relevant logs; distinguish test failures from environment/setup failures.
- [ ] Add further diagnostic-only tests if evidence exposes an untested boundary.
- [ ] Repeat CI after each diagnostic commit.

### Task 4: Technical findings report

**Files:**
- Create: `docs/reports/PROCESS-STABILITY-INVESTIGATION.md`

- [ ] Record source-level observations with exact file/line references.
- [ ] Record test names, commands, CI run identifiers, outcomes, and relevant logs.
- [ ] Classify each finding as confirmed, not reproduced, inconclusive, or deferred to host validation.
- [ ] Distinguish intentional behavior from correctness risks; do not claim a defect without reproducible evidence.
- [ ] Document required production changes as recommendations for Phase 1; do not implement them.
- [ ] State limitations of GitHub-hosted tests and any tests requiring a real Linux host or ClamAV installation.

### Task 5: Final verification and handoff

- [ ] Run focused and full CI checks on the investigation branch.
- [ ] Review the complete branch diff and verify no production files or shared workflows changed.
- [ ] Verify the PR remains open and Draft, with base `feature`.
- [ ] Use AI Delivery Evidence Checker against the recorded criteria, delivery summary, and test/CI evidence.
- [ ] Deliver a concise evidence-based verdict and Phase 1 implementation recommendations.

