## Unreleased

### Added
- Add explicit VirusTotal Public and Premium API profiles with independent OS Secret Service credentials.
- Add persistent profile-aware request pacing, Public daily quota enforcement, and cross-process Retry-After cooldowns.
- Add hash-first file submission workflow with per-file typed consent, privacy warning, SHA-256 revalidation, upload polling, CLI commands, and GTK profile selection.

- Add a persistent SHA-256-keyed VirusTotal report cache with a configurable 24-hour default TTL, acquisition-time expiry, and strict Public/Premium cache isolation.
- Run deduplicated VirusTotal hash lookups on a service-owned asyncio loop, independent of caller-loop cancellation or shutdown; drain and stop the worker during GTK application shutdown. Apply bounded retries for transient transport/server failures and HTTP 429 responses.
- Store VirusTotal reports independently by SHA-256 and API profile; migrate existing v1 cache databases transactionally while preserving acquisition and expiry timestamps.

### Security
- **Realtime descriptor worker admission:** bound active and queued descriptor workers (default limit: 4), reject excess scans explicitly, and retain each admission slot until the worker closes its duplicated descriptor after timeout or cancellation.
- **Realtime descriptor timeout and cleanup:** classify descriptor-scan timeouts as `TIMEOUT`, preserve the applied scan profile, prevent probe timeouts or cancellation from triggering INSTREAM fallback, and track worker completion through descriptor cleanup.
- **Realtime filesystem boundary:** pin configured monitoring roots, reject symlink roots/components, open event targets beneath root directory descriptors with `O_NOFOLLOW`, and use descriptor-bound clamd `FILDES` or `INSTREAM` scanning with no pathname fallback.
- Keep Public API requests blocked until written VirusTotal eligibility authorization is recorded.
- Remove upstream response bodies and sensitive request details from VirusTotal error logs; never fall back between API profiles.
- Keep VirusTotal enrichment separate from the local ClamAV verdict.

# Changelog

All notable changes to ClamGuardian are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
within the release numbering defined in [`docs/ROADMAP.md`](docs/ROADMAP.md).

## [Unreleased]

### Fixed
- **USB lifecycle and mount validation:** require an actual mount backed by removable/USB block-device identity beneath an allowed root; track background scan tasks, cancel them on unmount/shutdown, and prevent ordinary directories from being treated as removable devices.
- **Realtime lifecycle:** recreate the scan orchestrator on each start, fail startup when configured directories or recursive watches cannot be registered, and expose watch-registration failures instead of reporting incomplete monitoring as active.
- **Scheduled scans:** persist the last successful daily run across restarts and retry failed scans rather than recording a failed attempt as completed.
- **Background service integration:** start and stop USB, realtime and scheduler services from the GTK application lifecycle using the application's shared scan runner and history store; apply realtime path changes.
- **VirusTotal safety:** enforce opt-in in the CLI, cache the provider for a service lifetime, apply a shared, cross-process 15.1-second minimum request interval, add hidden-input Secret Service key setup, and keep all network lookups blocked until maintainer review confirms applicable Public API terms and product eligibility.
- **Flatpak credentials:** grant the Secret Service D-Bus name in both manifests; Secret Service availability checks now exercise the D-Bus operation and remain fail-closed.
- **Autostart:** reject unsupported host XDG autostart writes from inside Flatpak rather than silently claiming that host autostart was installed.

### Added
- **USB Auto-Scan (1.1)**: Removable media mount monitoring (`clamguardian/core/usb.py`), target safety validation, symlink traversal prevention, duplicate event suppression, and device disappearance handling. Integrated into GTK Settings and CLI (`clamguardian usb status/enable/disable/scan`).
- **Threat Intelligence (1.2)**: Opt-in VirusTotal v3 SHA-256 hash lookup integration with rate limiting, strict separation between local ClamAV verdicts and remote verdicts, OS Secret Service integration (`libsecret`), fail-closed security policy without plaintext fallback, and CLI commands (`clamguardian intel set-key/status/enable/disable/lookup`).
- **Realtime Event-Driven Monitoring (2.x-A)**: Native Linux `InotifyMonitor` using libc syscalls, `RealtimeScanOrchestrator` enforcing queue bound `pending + dispatched + active <= max_queue_depth`, trailing-edge push debouncing, same-path coalescing, dirty/retrigger active scan tracking, recursive watch tracking and cleanup, explicit `IN_Q_OVERFLOW` detection, and CLI subcommands (`clamguardian monitor status/enable/disable/add/remove`).
- **Scheduled Scans**: Unprivileged daily scheduled scan manager (`clamguardian/core/scheduler.py`) with missed-scan recovery, integrated with `ScanTaskRunner` and `HistoryStore`, exposed via GTK Settings and CLI (`clamguardian schedule status/enable/disable`).
- **User-Session Autostart**: Optional autostart manager (`clamguardian/core/autostart.py`) installing user-session desktop entries in `~/.config/autostart`, disabled by default, exposed via GTK Settings and CLI (`clamguardian autostart status/enable/disable`).
- **ClamUI Benchmark Evaluation**: Comprehensive evaluation matrix (`docs/reports/CLAMUI-BENCHMARK-EVALUATION.md`) detailing adopted, improved, rejected, and deferred capabilities.
- **Engineering Handoff**: Comprehensive technical documentation in `docs/engineering/CLAMGUARDIAN-AUTONOMOUS-COMPLETION-HANDOFF.md`.

## [1.0.1] — release candidate (tag cut after the manual desktop validation)

Security and desktop update. Prepared on 2026-10-20; the `v1.0.1` tag is created
from `main` only after the desktop validation recorded in
`docs/validation/DESKTOP-TEST-D4-2026-10-19.md` and the promotion PRs
(`feature → testing → development → main`). Release checklist:
[`docs/reports/RELEASE-1.0.1.md`](docs/reports/RELEASE-1.0.1.md).

### Security

- **AUD-01 (P1):** `clamd` responses are now read to EOF with an 8 MiB cap, so a
  directory scan with a clean file followed by an infected one no longer
  reports the directory as clean. **This defect is present in 1.0.0.**
- **AUD-02:** quarantine key handling uses `Secret.Schema` with attributes and
  logs when it degrades to the file fallback.
- **AUD-03:** the quarantine key is written atomically (`mkstemp` + `fchmod`
  `0600` + `fsync` + `os.replace`) and a corrupt key fails closed instead of
  being silently rotated.
- **AUD-04:** scan targets containing NUL, `\n` or `\r` are rejected before the
  `clamd` socket is written, closing protocol injection.
- **AUD-08/AUD-09:** quarantine restore is confined to absolute paths without
  `..`, and symlinks are rejected on ingest and restore.
- **AUD-10/AUD-12:** pre-existing history directories keep their mode; CLI and
  history output escape C0/DEL control characters.
- **AUD-14 (partial):** the environment passed to `flatpak-spawn --host` is
  sanitised.

### Added

- Complete GTK4/Libadwaita desktop application: Scan, History, Quarantine,
  Databases, Diagnostics and Settings pages, window chrome with `Adw.ToolbarView`,
  About dialog, packaged stylesheet with light/dark/system colour schemes,
  and opt-in content-free scan-completion notifications.
- Quarantine ingest straight from the Scan page threat list.
- Persisted desktop preferences (`default_profile_id`, `notifications_enabled`,
  `color_scheme`) in a strict `0600` JSON store.
- GTK smoke job in the release gate now constructs **every** page, the settings
  store, the stylesheet and the About dialog (previously shell, diagnostics and
  scan only).
- Packaging guard test: the release Flatpak manifest must pin `v<current version>`.

### Fixed

- History and Quarantine lists populate again (the D3 completion callbacks
  discarded results).
- Restore and delete wrap the synchronous vault calls instead of running them on
  the GTK main loop.

### Changed

- Threat intelligence remains frozen and unwired; the `intelligence` extra still
  installs nothing (Phase 11, `v1.2.0`).

## [1.0.0] — 2026-10-16

First stable release: profile-aware scan history, SHA-256 content hashing,
AES-256-GCM quarantine vault with chunked streaming, ClamAV engine integration
with Flatpak-aware host execution, and a pinned dependency audit in CI.
Tag `v1.0.0` → commit `8ee8a56`; evidence
[`docs/reports/RELEASE-GATE-1.0.md`](docs/reports/RELEASE-GATE-1.0.md).
