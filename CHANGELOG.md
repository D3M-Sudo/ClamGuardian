# Changelog

All notable changes to ClamGuardian are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
within the release numbering defined in [`docs/ROADMAP.md`](docs/ROADMAP.md).

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
