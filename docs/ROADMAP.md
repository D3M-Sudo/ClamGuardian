# ClamGuardian Implementation Roadmap

This document outlines the authoritative development roadmap for ClamGuardian, tracking completed milestones, in-progress targets, and future architectural phases.

---

## Roadmap Overview

```
M0 → M0.5 → F0 → M1 → M2 → M3 → M4-A → M4-B (B1..B7) [COMPLETED]
    ↓
Phase 1: M4 Profile Propagation [NEXT]
Phase 2: M4 Content Hashing [PENDING]
Phase 3: M4 Security Test Gap Closure [PENDING]
Phase 4: M4 Finalization & Report [PENDING]
    ↓
Phase 5: M5 Security Hardening [PENDING]
Phase 6: M5 P2 Evaluation [PENDING]
Phase 7: M6 CI & Quality Gates [PENDING]
Phase 8: M7 Packaging [PENDING]
Phase 9: 1.0 Release Gate [PENDING]
    ↓
Phase 10: 1.1 USB Auto-Scan [PENDING]
Phase 11: Threat Intelligence Integration [PENDING]
Phase 12: 2.x-A Event-Driven Monitoring [PENDING]
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
- **Status:** NEXT
- **Scope:** Ensure scan profile information (`profile_id`, `profile_snapshot`) flows deterministically from Scan Request → ScanProfile → ScanTaskRunner → Engine → ScanResult → History.
- **Dependencies:** M4-B history layer.

### Phase 2: M4 Content Hash Model
- **Status:** PENDING
- **Scope:** Compute SHA-256 for single-file scan artifacts (`sha256=<digest>`); set `sha256=None` for directory scans.
- **Dependencies:** Phase 1.

### Phase 3: M4 Security Test Gap Closure
- **Status:** PENDING
- **Scope:** Audit and add comprehensive tests for Quarantine (ciphertext, corrupted auth, path traversal, TOCTOU), Database updates (checksum mismatch, rollback), Engine (Flatpak host execution), and Filesystem (special files, symlinks, FIFOs, sockets, devices).
- **Dependencies:** Phase 2.

### Phase 4: M4 Finalization & Report
- **Status:** PENDING
- **Scope:** Verify Core/Engine/History boundary isolation, run full quality gates, produce M4 Report.
- **Dependencies:** Phase 3.

### Phase 5 & 6: M5 Security Hardening & P2 Evaluation
- **Status:** PENDING
- **Scope:** Quarantine streaming/chunked AES-256-GCM encryption, database download integrity, explicit scan target validation (handling special files/symlinks), host execution hardening, intelligence trust boundaries, P2 evaluation.
- **Dependencies:** Phase 4.

### Phase 7: M6 CI & Quality Gates
- **Status:** PENDING
- **Scope:** Integrate `mypy` and `pip-audit` into GitHub Actions CI pipeline.
- **Dependencies:** Phase 5 & 6.

### Phase 8 & 9: M7 Packaging & 1.0 Release Gate
- **Status:** PENDING
- **Scope:** Desktop metadata, icon, Flatpak manifest, 1.0 release readiness audit & gate.
- **Dependencies:** Phase 7.

### Phase 10: 1.1 USB Auto-Scan
- **Status:** PENDING
- **Scope:** Device/mount detection, target validation, task runner scan triggering for removable media.
- **Dependencies:** 1.0 Release Gate.

### Phase 11: Threat Intelligence Integration
- **Status:** PENDING
- **Scope:** Explicit VirusTotal SHA-256 lookup integration using content-hash seam, with opt-in policy and rate limiting.
- **Dependencies:** Phase 10.

### Phase 12: 2.x-A Event-Driven Monitoring
- **Status:** PENDING
- **Scope:** Linux `inotify` monitoring module (`clamguardian/realtime/`), event normalization, debouncing, deduplication, and task runner orchestration.
- **Dependencies:** Phase 11.

---

## Deferred Phases (Out of Scope for 2.x-A)

### 2.x-B: Access Prevention (fanotify / clamonacc)
- **Status:** DEFERRED
- **Reason:** Requires architectural review of root privileges / on-access blocking.

### 2.x-C: Privileged IPC Service / Daemon / Polkit
- **Status:** DEFERRED
- **Reason:** Requires separate system security architecture decision.
