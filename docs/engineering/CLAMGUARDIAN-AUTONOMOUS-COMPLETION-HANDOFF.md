# ClamGuardian — Autonomous Product Completion & Engineering Handoff

**Repository:** `D3M-Sudo/ClamGuardian`
**Working Branch:** `jules-13071147660288587292-a42f824c`
**Target Branch:** `feature`
**Baseline HEAD Commit:** `27346d1821f6bc728c4100822c5da251f473359d`
**Execution Mode:** Full autonomy
**Status:** **HISTORICAL SNAPSHOT — SUPERSEDED (2026-11-12)** — This handoff records the implementation and remediation state observed on 2026-11-09. PR #18 and later integration/remediation PRs have since been merged to `feature`, including VirusTotal dual profiles, shared scan enrichment, descriptor-based realtime enrichment and scan-linked evidence persistence. The status tables and test counts below are historical evidence and must not be read as the current branch state. Use `docs/ROADMAP.md` for the current implementation/release distinction.

---

### Audit and remediation status snapshot (2026-11-09; historical)

- PR #18 is the active remediation vehicle. The original green CI/Release Gate results apply only to the pre-remediation head; all new commits require fresh validation.
- VirusTotal outbound calls are administratively blocked until the maintainer completes the applicable Public API terms and product-eligibility review. Selecting the provider does not establish legal eligibility.
- USB auto-scan now requires a real mount point and tracks cancellation; realtime startup fails closed when a configured watch cannot be installed; scheduler state persists the last successful daily run.
- GTK background-service behavior still requires explicit real-host validation; CI smoke coverage is not equivalent to manual desktop validation.
- Flatpak autostart via direct host XDG autostart writes is explicitly unsupported and rejected; a supported Background portal integration remains a separate implementation requirement.
- This historical handoff does not itself imply release promotion or a published release.

## 1. Project Status Summary

| Area | Status | Evidence | Notes |
|---|---|---|---|
| **Stabilization & Baseline Reconciliation** | COMPLETE | pytest (351 passed, 13 skipped), mypy 54 files clean, ruff clean, `uv lock --check` clean, `pip-audit --strict` clean | Clean initial state, historical P1/P2 defect analysis closed. |
| **Phase 1: USB Auto-Scan (1.1)** | REMEDIATION IN PROGRESS | `clamguardian/core/usb.py`, `tests/test_usb.py`, CLI `clamguardian usb ...`, Settings integration | Safe mount validation strictly under standard roots, symlink protection, duplicate event suppression, graceful device disappearance handling. |
| **Phase 2: Threat Intelligence (1.2)** | BLOCKED — terms review | `clamguardian/intelligence/`, `tests/test_intelligence.py`, CLI `clamguardian intel ...`, Settings integration | VirusTotal v3 provider with rate limiting, SHA-256 hash-only lookups (no file content uploads), fail-closed Secret Service credential storage (zero plaintext fallback), zero network requests when disabled. |
| **Phase 3: Realtime Monitoring (2.x-A)** | REMEDIATION IN PROGRESS | `clamguardian/realtime/`, `tests/test_realtime.py`, CLI `clamguardian monitor ...`, Settings integration | Strict queue invariant `pending + dispatched + active <= max_queue_depth`, push-driven trailing-edge debounce, same-path coalescing, dirty/retrigger handling during active scans, recursive libc inotify watch tracking, `IN_Q_OVERFLOW` detection, deterministic shutdown. |
| **Phase 4: ClamUI Benchmark Enhancements** | REMEDIATION IN PROGRESS | `clamguardian/core/scheduler.py`, `clamguardian/core/autostart.py`, `tests/test_scheduler.py`, CLI `schedule`/`autostart`, `docs/reports/CLAMUI-BENCHMARK-EVALUATION.md` | Unprivileged daily scheduled scan manager with missed-scan recovery, XDG user-session autostart manager (`~/.config/autostart`), disabled by default. |
| **Phase 5: Desktop & CLI Integration & Packaging** | REMEDIATION IN PROGRESS | `clamguardian/cli/main.py`, `clamguardian/ui/settings_page.py`, `tests/test_packaging.py`, wheel build verified | All 10 CLI command groups functional with human and JSON output; desktop Settings exposes automation toggles; packaging manifests valid. |

---

## 2. Implementation Inventory

### 2.1 Core Subsystems
- **`clamguardian/core/usb.py`**:
  - `USBDeviceScanner`: target validation, symlink traversal refusal, duplicate suppression, disappearance handling, `ScanTaskRunner` and `HistoryStore` integration.
  - `USBMountMonitor`: unprivileged poll loop over `/proc/mounts`, detecting new removable mounts under allowed roots (`/media`, `/run/media`, `/mnt`).
- **`clamguardian/core/scheduler.py`**:
  - `ScheduledScanManager`: user-level daily scheduled scans, missed-scan boundary evaluation, non-blocking background loop.
- **`clamguardian/core/autostart.py`**:
  - `AutostartManager`: management of unprivileged user desktop autostart via `~/.config/autostart/io.github.clamguardian.ClamGuardian.desktop`.
- **`clamguardian/core/settings.py`**:
  - Extended `AppSettings` schema to persist `usb_autoscan_enabled`, `intelligence_enabled`, `realtime_enabled`, `realtime_paths`, `scheduled_scans_enabled`, `scheduled_hour`, `scheduled_minute`, and `autostart_enabled`.

### 2.2 Threat Intelligence
- **`clamguardian/intelligence/secrets.py`**:
  - `IntelligenceSecretStore`: strict integration with OS Secret Service (`libsecret`); fails closed with `SecretStorageError` if unavailable; no plaintext fallback on disk.
- **`clamguardian/intelligence/virustotal.py`**:
  - `VirusTotalProvider`: v3 API integration, SHA-256 hash lookup only, rate limiting via `_enforce_rate_limit()` lock, clear separation from local engine verdicts.
- **`clamguardian/intelligence/service.py`**:
  - `ThreatIntelligenceService`: high-level service querying threat intelligence for single files when enabled; zero network calls when disabled.

### 2.3 Realtime Filesystem Monitoring (2.x-A)
- **`clamguardian/realtime/events.py`**: Normalized `FileEvent` and `FileEventType` dataclasses.
- **`clamguardian/realtime/monitor.py`**: Abstract `FileMonitor` contract.
- **`clamguardian/realtime/policy.py`**: `RealtimePolicy` filtering ignored suffixes (`.tmp`, `.swp`, `.part`, `.db-wal`, etc.) and paths.
- **`clamguardian/realtime/inotify.py`**: Native Linux `InotifyMonitor` using libc syscalls (`inotify_init1`, `inotify_add_watch`, `inotify_rm_watch`), recursive directory watch discovery, watch cleanup on move-out/deletion, and explicit `IN_Q_OVERFLOW` counting.
- **`clamguardian/realtime/orchestrator.py`**: `RealtimeScanOrchestrator` enforcing `pending + dispatched + active <= max_queue_depth`, trailing-edge debounce timers, same-path coalescing, dirty/retrigger tracking for active scans, and deterministic `close()` awaiting all tasks.
- **`clamguardian/realtime/service.py`**: `RealtimeMonitorService` unifying monitor, policy, orchestrator, and `ScanTaskRunner`.

### 2.4 Desktop & CLI Integration
- **`clamguardian/cli/main.py`**:
  - Added CLI subcommands: `usb status/enable/disable/scan`, `intel status/enable/disable/lookup`, `monitor status/enable/disable/add/remove`, `schedule status/enable/disable`, and `autostart status/enable/disable`.
- **`clamguardian/ui/settings_page.py`**:
  - Added "Automation & Protection" group exposing switches for USB Auto-Scan, Threat Intelligence, Realtime Monitoring, Daily Scheduled Scans, and Autostart at Login.

---

## 3. Architectural Decisions & Constraints

1. **Unprivileged Architecture**:
   - No root execution or setuid components introduced.
   - Realtime monitoring uses user-space inotify; USB monitoring reads `/proc/mounts`; scheduled scans run in user session; autostart uses standard XDG user desktop entries.
2. **Strict Queue Invariant**:
   - `total_outstanding_work = len(pending) + len(dispatched) + len(active) <= max_queue_depth`.
   - Debounce timer expiration immediately transitions paths from `_pending_events` to `_dispatched`, ensuring no untracked gap between timer firing and task execution.
3. **Seam Isolation & Privacy**:
   - Threat intelligence lookups require explicit user opt-in (`intelligence_enabled=True`). When disabled, `ThreatIntelligenceService.lookup_scan_result()` returns `None` with zero network requests.
   - Threat intelligence sends only 64-character hexadecimal SHA-256 digests; file contents are never uploaded.
   - ClamAV scan results and remote VirusTotal verdicts are stored in separate attributes and never override each other.

---

## 4. Verification & Test Evidence

| Test Suite / Tool | Command Executed | Result | Details |
|---|---|---|---|
| **pytest (Complete)** | `uv run --extra test pytest` | **351 passed, 13 skipped** (4.81s) | All core, engine, history, CLI, quarantine, databases, packaging, USB, intelligence, realtime, and scheduler tests passed. 13 skipped require PyGObject/display. |
| **ruff (Linting & Formatting)** | `uv run ruff check .` | **All checks passed!** | Clean codebase compliant with project style rules. |
| **mypy (Type Checking)** | `uv run --extra test mypy clamguardian` | **Success: no issues found in 54 source files** | Strict typing verified across all modules. |
| **uv Lockfile Verification** | `uv lock --check` | **Resolved 55 packages (Clean)** | Lockfile matches `pyproject.toml`. |
| **pip-audit (Security)** | `pip-audit --strict -r <(uv export ...)` | **No known vulnerabilities found** | Zero known vulnerabilities in pinned runtime set. |
| **Packaging & Distribution** | `tests/test_packaging.py` + `uv build` | **17 passed** + wheel/sdist generated | Valid AppStream metainfo, desktop launcher, icons, and permissions. |

---

## 5. ClamUI Functional Benchmark Findings

The functional benchmark evaluation was completed and recorded in `docs/reports/CLAMUI-BENCHMARK-EVALUATION.md`:
- **Adopted & Implemented**: USB Auto-Scan, optional Threat Intelligence lookups, Realtime event-driven inotify monitoring, daily scheduled scans, user-session autostart.
- **Rejected**: Privileged background IPC daemons / Polkit integration (violates ClamGuardian's unprivileged security model).
- **Deferred**: `fanotify`/`clamonacc` on-access prevention (requires root privilege; 2.x-B scope).

---

## 6. Known Environmental Limitations

- **Headless Environment**: The test runner operates in a headless Linux container without PyGObject/GTK4 libraries and display server (`Xvfb`). Headless shims allow all logic and CLI commands to be thoroughly tested; live desktop GUI rendering can be validated on a host with `gir1.2-gtk-4.0` and `gir1.2-adw-1`.
- **ClamAV Daemons**: System `clamd` and `clamscan` binaries are not preinstalled on the sandbox container. Engine fallback and process lifecycles are verified using the comprehensive engine mock and subprocess test suite.
