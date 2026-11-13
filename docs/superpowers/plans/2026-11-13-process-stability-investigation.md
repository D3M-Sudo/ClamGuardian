# Process Stability Investigation Plan

> **For agentic workers:** Execute this plan task-by-task. Each task is restricted to the isolated `investigation/process-stability` branch.

**Goal:** Produce reproducible, CI-backed evidence about ClamGuardian subprocess, timeout, output, cancellation, fallback, and scheduling behavior without changing production code.

**Architecture:** Characterize the existing implementation through isolated diagnostic tests and deterministic child-process fixtures. Record confirmed behavior, failures, and limitations in a technical report; defer all production fixes to the later Phase 1 implementation.

**Tech Stack:** Python 3.11+, asyncio, pytest, pytest-asyncio, GitHub Actions.

**Spec:** User-approved scope in the ClamGuardian process-stability investigation conversation.

## Global Constraints

- Base branch: `feature`; investigation branch: `investigation/process-stability`.
- All commits and files remain on `investigation/process-stability`.
- No production-code changes.
- Allowed files: diagnostic tests, fixtures, scripts/tools, and technical documentation.
- Do not modify shared workflow configuration or any existing branch.
- Open a Draft PR targeting `feature`; never mark ready, approve, close, or merge it.
- Use GitHub Actions triggered by the Draft PR to test the investigation head; report any trigger limitations.

## Review Focus

- A child process emits progress continuously but still reaches the configured absolute timeout.
- A command emits large stdout and stderr streams; memory capture and stream handling remain bounded or demonstrably unbounded.
- A clamd timeout or protocol failure triggers or does not trigger a CLI fallback, with cancellation kept distinct.
- A parent process exits on SIGTERM while a descendant ignores SIGTERM; no descendant should be left running.
- Cancellation while waiting for the runner concurrency slot does not leak a slot or leave a scan running.
- Scheduler shutdown while a scan is active propagates cancellation through the runner and engine.

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

