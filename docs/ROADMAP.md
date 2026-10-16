# ClamGuardian Implementation Roadmap

This document outlines the authoritative development roadmap for ClamGuardian, tracking completed milestones, in-progress targets, and future architectural phases.

---

## Roadmap Overview

```
M0 → M0.5 → F0 → M1 → M2 → M3 → M4-A → M4-B (B1..B7) [COMPLETED]
    ↓
Phase 1: M4 Profile Propagation [COMPLETED]
Phase 2: M4 Content Hashing [COMPLETED]
Phase 3: M4 Security Test Gap Closure [COMPLETED]
Phase 4: M4 Finalization & Report [COMPLETED]
    ↓
Phase 5: M5 Security Hardening [COMPLETED]
Phase 6: M5 P2 Evaluation [COMPLETED]
Phase 7: M6 CI & Quality Gates [COMPLETED]
Phase 8: M7 Packaging [COMPLETED]
Phase 9: 1.0 Release Gate [COMPLETED 2026-10-16 — tag v1.0.0 @ 8ee8a56, installable Flatpak bundle]
    ↓
Phase 10: 1.1 USB Auto-Scan [DEFERRED - out of 1.0 scope]
Phase 11: Threat Intelligence Integration [DEFERRED - out of 1.0 scope]
Phase 12: 2.x-A Event-Driven Monitoring [DEFERRED - out of 1.0 scope]
    ↓
2.x-B / 2.x-C [DEFERRED]
```

---

## Completed Milestones

### M0: Repository Initialization
- **Objective:** Establish Python project structure, packaging layout, license, and initial CI setup.
- **Status:** COMPLETED

### M0.5: ClamAV Engine Abstraction
- **Objective:** Implement `BaseAVEngine` interface and `ClamAVEngine` supporting hybrid clamd UNIX socket execution with `clamscan` fallback.
- **Status:** COMPLETED

### F0: Architecture Freeze v1
- **Objective:** Freeze foundational architecture: Core owns scan models, Engine owns ClamAV execution, History owns persistence, UI owns GTK presentation.
- **Status:** COMPLETED

### M1: Asynchronous ScanTaskRunner & Cancellation
- **Objective:** Implement bounded concurrency, queueing, process-group SIGTERM/SIGKILL termination, and cancellation.
- **Status:** COMPLETED

### M2: Profile Infrastructure & Preset Models
- **Objective:** Implement `ScanProfile` model, preset registry (`quick`, `home`, `full`, `custom`), validation, and engine translation.
- **Status:** COMPLETED

### M3: Subprocess Security & Flatpak Host Execution
- **Objective:** Implement safe subprocess execution, arguments translation, process-group isolation, and `flatpak-spawn --host` support.
- **Status:** COMPLETED

### M4-A: History Schema Design & Budgets
- **Objective:** Define history persistence schema v1, budget caps (~8 KiB JSON columns), and data models.
- **Status:** COMPLETED

### M4-B1 → M4-B7: SQLite History Persistence & Subcommands
- **Objective:** Implement `HistoryStore` protocol, `SqliteHistoryStore` backend (WAL, foreign keys, `0o700` dir permissions), CLI subcommands (`history list`, `history show`, `history purge`), and background recording.
- **Status:** COMPLETED

---

## Active & Pending Roadmap Phases

### Phase 1: M4 Profile-Aware History Propagation
- **Status:** COMPLETED
- **Scope:** Ensure scan profile information (`profile_id`, `profile_snapshot`) flows deterministically from Scan Request → ScanProfile → ScanTaskRunner → Engine → ScanResult → History.
- **Dependencies:** M4-B history layer.
- **Evidence:** `docs/M4-FINAL-REPORT.md` (fixes `81ea321`, `88a57a6`).

### Phase 2: M4 Content Hash Model
- **Status:** COMPLETED
- **Scope:** Compute SHA-256 for single-file scan artifacts (`sha256=<digest>`); set `sha256=None` for directory scans.
- **Dependencies:** Phase 1.
- **Evidence:** `docs/M4-FINAL-REPORT.md`; digest now recorded on both engine backends.

### Phase 3: M4 Security Test Gap Closure
- **Status:** COMPLETED
- **Scope:** Audit and add comprehensive tests for Quarantine (ciphertext, corrupted auth, path traversal, TOCTOU), Database updates (checksum mismatch, rollback), Engine (Flatpak host execution), and Filesystem (special files, symlinks, FIFOs, sockets, devices).
- **Dependencies:** Phase 2.
- **Evidence:** `docs/M4-FINAL-REPORT.md`; provider-level digest enforcement tests added. Database digest optionality is an M5 item (see report, section 5).

### Phase 4: M4 Finalization & Report
- **Status:** COMPLETED
- **Scope:** Verify Core/Engine/History boundary isolation, run full quality gates, produce M4 Report.
- **Dependencies:** Phase 3.
- **Evidence:** `docs/M4-FINAL-REPORT.md`; boundaries verified, quality gates green (203 passed / 2 skipped, ruff, mypy on 26 source files).

### Phase 5 & 6: M5 Security Hardening & P2 Evaluation
- **Status:** COMPLETED
- **Scope:** Quarantine streaming/chunked AES-256-GCM encryption, database download integrity, explicit scan target validation (handling special files/symlinks), host execution hardening, intelligence trust boundaries, P2 evaluation.
- **Dependencies:** Phase 4.
- **Evidence:** `docs/M5-HARDENING-REPORT.md`; fixes `3394f86`, `192695c`, `d1a5cb3`, `b21e320`.

### Phase 7: M6 CI & Quality Gates
- **Status:** COMPLETED
- **Scope:** Integrate `mypy` and `pip-audit` into GitHub Actions CI pipeline.
- **Dependencies:** Phase 5 & 6.
- **Evidence:** `docs/M6-CI-GATE-REPORT.md`; dedicated `audit` job on the pinned lockfile (`uv lock --check` + `pip-audit --strict -r`), `test` job on Python 3.11/3.12/3.13. **Closed by execution:** CI run `38493461942` on `9832b4d` — `audit` job green (`pip-audit --strict`: "No known vulnerabilities found"), `test` green on 3.11/3.12/3.13 (247 tests each).

### Phase 8 & 9: M7 Packaging & 1.0 Release Gate
- **Status:** COMPLETED (both) — 2026-10-16
- **Scope:** Desktop metadata, icon, Flatpak manifest, 1.0 release readiness audit & gate.
- **Dependencies:** Phase 7.
- **Evidence:** `docs/M7-PACKAGING-REPORT.md`; `tests/test_packaging.py` (16 tests); wheel built, installed and run end to end; Release Gate CI (`.github/workflows/release-gate.yml`) — 7 jobs on the final tag run `38977065253` (`v1.0.0` @ `8ee8a56`; an earlier green tag run `38975655153` validated `745e1e7`): preflight, GNOME 51 offline Flatpak build (local manifest), AppStream validation, real ClamAV (clamscan + clamd, clean + EICAR), GTK smoke, release-manifest build pinned to the tag, and gate summary — all green. Deliverable: `ClamGuardian-v1.0.0-linux-x86_64.flatpak` (installable bundle, ~4.7 MB). The first tag run failed on a `cffi` cp312 wheel left in the release manifest only (404 on first-ever download of those sources); the fix (`cffi` cp314 in both manifests) shipped in `745e1e7` with two guard tests (manifest parity + runtime platform tags), then the tag was re-pointed to the fixed commit and finally to the release docs commit `8ee8a56`, each position re-validated by a green tag run.
- The checklist, the per-gate evidence and the procedure for each gate live in **`docs/RELEASE-GATE-1.0.md`**.

### Phase 10: 1.1 USB Auto-Scan
- **Status:** DEFERRED (out of 1.0 scope)
- **Scope:** Device/mount detection, target validation, task runner scan triggering for removable media.
- **Dependencies:** 1.0 Release Gate.
- **Note:** An implementation existed on the PR #5 branch and survives in git history — reachable from the annotated tag `audit/pr5-2026-10-12`. It is not part of the 1.0 branch (nothing in the CLI/UI consumed it) and will be reintroduced with its own gate and call site.

### Phase 11: Threat Intelligence Integration
- **Status:** DEFERRED (out of 1.0 scope)
- **Scope:** Explicit VirusTotal SHA-256 lookup integration using content-hash seam, with opt-in policy and rate limiting.
- **Dependencies:** Phase 10.
- **Note:** The `clamguardian.intelligence` package is present on the 1.0 branch but **unwired**: nothing in the CLI or UI imports it, and no distribution declares the `clamguardian.threat_providers` entry-point group it discovers, so it is not reachable in the 1.0 release. The Core seam `BaseThreatProvider` (`core/base.py`) is the extension contract. The phase returns with its own call site and gate.

### Phase 12: 2.x-A Event-Driven Monitoring
- **Status:** DEFERRED (out of 1.0 scope)
- **Scope:** Linux `inotify` monitoring module (`clamguardian/realtime/`), event normalization, debouncing, deduplication, and task runner orchestration.
- **Dependencies:** Phase 11.
- **Note:** The `clamguardian/realtime` package is not part of the 1.0 branch: it is unwired and still carries open P1 defects (duplicate dispatch, queue bound, shutdown, stale watches, silent inotify overflow). It returns with the remediation tracked in the PR #5 audit report (archived under the annotated tag `audit/pr5-2026-10-12`).

---

## Deferred Phases (Out of Scope for 2.x-A)

### 2.x-B: Access Prevention (fanotify / clamonacc)
- **Status:** DEFERRED
- **Reason:** Requires architectural review of root privileges / on-access blocking.

### 2.x-C: Privileged IPC Service / Daemon / Polkit
- **Status:** DEFERRED
- **Reason:** Requires separate system security architecture decision.
