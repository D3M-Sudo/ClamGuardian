# ClamGuardian Master Project Plan

## 1. Project Overview & Objectives

**ClamGuardian** is an open-source Linux security application providing high-performance antivirus scanning, quarantine vaulting, threat intelligence, and event-driven filesystem monitoring for Linux desktop and server environments.

Key objectives:
- **Safety & Performance:** Hybrid ClamAV engine prioritizing `clamd` UNIX sockets with transparent `clamscan` fallback.
- **Privacy & Security:** Authenticated AES-256-GCM encrypted quarantine vaulting without unprivileged key leakage.
- **Clean Architecture:** Strict decoupling between Core models, Engine execution, History persistence, UI presentation, and Realtime filesystem monitoring.
- **Flatpak Compatibility:** Native support for running inside Flatpak sandboxes via `flatpak-spawn --host`.

---

## 2. Architectural Boundaries & Binding Constraints

```
                            CLAMGUARDIAN
                                 │
                 ┌───────────────┼───────────────┐
                 │               │               │
            Interactive      Automatic        System
                 │               │            (future)
          ┌──────┴──────┐        │               │
         CLI           GTK      USB              │
          └──────┬──────┴────────┘               │
                 ▼                               │
         Scan Orchestration                      │
                 │                               │
         ScanTaskRunner                          │
                 │                               │
        ┌────────┴────────┐                      │
        │                 │                      │
   Orchestrator     RealtimeScan                 │
        │           (inotify)                    │
        │                 │                      │
        └────────┬────────┘                      │
                 ▼                               │
           ClamAV Engine                         │
                 │                               │
            ScanResult                           │
                 │                               │
    ┌────────────┼────────────┐                  │
    ▼            ▼            ▼                  │
 History     Quarantine  Intelligence            │
```

### Module Responsibilities:
1. **Core (`clamguardian/core`):**
   - Owns scan models (`ScanResult`, `ScanProgress`, `ScanStatus`), scan profiles (`ScanProfile`), profile registry, and task execution primitives (`ScanTaskRunner`).
   - Must NOT depend on SQLite, GTK, CLI, or Linux realtime implementations.
2. **Engine (`clamguardian/engines`):**
   - Owns ClamAV interactions (`clamd` UNIX socket & `clamscan` process execution).
   - Translates `ScanProfile` into engine arguments.
   - Must NOT depend on History, SQLite, GTK, or CLI.
3. **History (`clamguardian/history`):**
   - Owns persistent history storage using SQLite.
   - Must NOT execute scans or modify `ScanResult` semantics.
4. **Quarantine (`clamguardian/core/quarantine.py`):**
   - Owns AES-256-GCM file encryption and metadata vault management.
5. **UI (`clamguardian/ui`):**
   - GTK4 / Libadwaita presentation controller and views.
   - Must be import-safe on headless systems without PyGObject.
6. **Realtime (`clamguardian/realtime`):**
   - Owns `inotify` event-driven filesystem monitoring, debouncing, deduplication, and policy filtering. Reuses `ScanTaskRunner`.

---

## 3. Security & Hardening Strategy

- **Unprivileged Execution:** Runs completely in user space without root, setuid, Polkit, or system daemon privileges.
- **Subprocess Isolation:** Executed subprocesses (`clamscan`, `freshclam`) use `start_new_session=True` for process-group signal containment (SIGTERM grace period followed by SIGKILL).
- **Quarantine Security:** AES-256-GCM encryption with random 12-byte nonces, serialized AAD header, owner-only directory (`0o700`) and file (`0o600`) permissions, atomic file replacement, and path traversal validation.
- **Target Validation:** Verification of file types prior to scanning to ensure special devices, FIFOs, and sockets are handled explicitly and safely.

---

## 4. Testing & Verification Strategy

- **Automated Unit & Integration Tests:** Pytest suite covering core models, profiles, engine execution, cancellation, quarantine, history backend, CLI commands, and UI controllers.
- **Headless Safety:** UI components degrade gracefully on systems missing GTK/PyGObject, maintaining testability.
- **Static Analysis & Type Checking:**
  - Code formatting & linting: `ruff check .`
  - Type verification: `mypy clamguardian`
  - Dependency vulnerability auditing: `pip-audit` in CI.

---

## 5. Packaging & Distribution Strategy

- **Authoritative Version:** Defined in `pyproject.toml`.
- **Desktop Integration:** Desktop entry and app metadata for Linux desktop environments.
- **Flatpak Sandbox Compatibility:** CLI and UI support host invocation via `flatpak-spawn --host`.

---

## 6. Post-1.0 Evolution & Boundaries

- **1.1 USB Auto-Scan:** Automatic detection and scanning of mounted removable volumes using existing `ScanTaskRunner`.
- **1.x Threat Intelligence:** VirusTotal SHA-256 lookup integration using content-hash seam with explicit user opt-in.
- **2.x-A Event-Driven Monitoring:** Native Linux `inotify` event monitoring behind `FileMonitor` and `RealtimeScanOrchestrator`.
- **Explicit Non-Goals / Deferred Features:**
  - No `Maldet`/`LMD` dependencies.
  - No root daemon / Polkit / systemd system service in 2.x-A.
  - No `fanotify` on-access blocking in 2.x-A.
