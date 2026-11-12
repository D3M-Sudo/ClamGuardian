# Changelog

All notable changes to ClamGuardian are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
within the release numbering defined in [`docs/ROADMAP.md`](docs/ROADMAP.md).

## [Unreleased]

### Added

- **Industrial CI/CD release pipeline:** native x86_64/aarch64 Flatpak and AppImage builds, lockfile-hash-verified runtime wheelhouses, per-artifact install/launch gates, Draft GitHub Releases, SHA-256 checksums and one explicit manual publication workflow.
- **VirusTotal API profiles and file submission:** independent Public/Premium credentials in OS Secret Service, explicit profile selection, hash-first lookup and consent-gated upload with snapshot revalidation and analysis polling.
- **VirusTotal hash cache:** persistent, profile-isolated hash assessments with shared in-flight lookup deduplication and bounded transient retries.
- **Shared scan enrichment:** centralize optional VirusTotal enrichment across pathname and descriptor-based scan workflows while preserving the local ClamAV verdict and request-time profile/provenance.
- **Persistent intelligence evidence:** store normalized VirusTotal assessments in a scan-linked SQLite table with schema migration and retention lifecycle; expose retrieval through the HistoryStore interface.
- **USB Auto-Scan (1.1):** removable-media mount monitoring (`clamguardian/core/usb.py`), target safety validation, symlink traversal prevention, duplicate event suppression, and device disappearance handling. Integrated into GTK Settings and CLI (`clamguardian usb status/enable/disable/scan`).
- **Threat Intelligence (1.2):** opt-in VirusTotal v3 SHA-256 hash lookup integration with rate limiting, strict separation between local ClamAV verdicts and remote verdicts, OS Secret Service integration (`libsecret`), fail-closed security policy without plaintext fallback, and CLI commands (`clamguardian intel set-key/status/enable/disable/lookup`).
- **Realtime Event-Driven Monitoring (2.x-A):** native Linux `InotifyMonitor` using libc syscalls, `RealtimeScanOrchestrator` enforcing queue bound `pending + dispatched + active <= max_queue_depth`, trailing-edge push debouncing, same-path coalescing, dirty/retrigger active scan tracking, recursive watch tracking and cleanup, explicit `IN_Q_OVERFLOW` detection, and CLI subcommands (`clamguardian monitor status/enable/disable/add/remove`).
- **Scheduled Scans:** unprivileged daily scheduled scan manager (`clamguardian/core/scheduler.py`) with missed-scan recovery, integrated with `ScanTaskRunner` and `HistoryStore`, exposed via GTK Settings and CLI (`clamguardian schedule status/enable/disable`).
- **User-Session Autostart:** optional autostart manager (`clamguardian/core/autostart.py`) installing user-session desktop entries in `~/.config/autostart`, disabled by default, exposed via GTK Settings and CLI (`clamguardian autostart status/enable/disable`).
- **ClamUI Benchmark Evaluation:** comprehensive evaluation matrix (`docs/reports/CLAMUI-BENCHMARK-EVALUATION.md`) detailing adopted, improved, rejected, and deferred capabilities.
- **Engineering Handoff:** comprehensive technical documentation in `docs/engineering/CLAMGUARDIAN-AUTONOMOUS-COMPLETION-HANDOFF.md`.
- **AppImage license and SBOM evidence:** stage the complete project GPL license, collect copyright documents for Debian packages that own bundled AppDir files, generate Syft SPDX 2.3 and CycloneDX 1.6 AppDir inventories, and publish aggregate SBOMs that also represent the AppImage Type 2 runtime. Bind the evidence to the final artifact SHA-256 and verify it during native CI.
- **AppImage release evidence:** attach architecture-specific SPDX/CycloneDX SBOM and license-evidence archives to Draft releases, with strict artifact cardinality checks and release-level SHA-256 verification.
- **SPDX semantic validation:** validate license identifiers against the pinned SPDX License List, require actual extracted text for unresolved LicenseRefs, and enforce the `NONE`/`NOASSERTION` operator restrictions.
- **AppImage Type 2 relink evidence:** attach per-architecture source bundles with the pinned runtime source, libfuse and patch, squashfuse, static dependency source snapshots, build inputs and checksums; unresolved mimalloc source identity remains explicit.

### Changed

- **AppImage Debian copyright parsing:** distinguish DEP-5 package-level header declarations from file-scoped `Files` declarations and stand-alone license-text paragraphs; retain `NOASSERTION` for partial coverage or mixed file-level licenses.
- **AppImage runtime provenance:** distinguish binary package, source package, upstream version and exact Alpine APK revision; correct zstd to the version identified in the packaged runtime evidence and keep mimalloc version unknown without installed-package proof.
- **Embedded libmpdec evidence:** identify libmpdec 2.5.1 from the CPython 3.12.3 source header and recognize BSD-2-Clause only when the scoped Debian notice contains both redistribution conditions and the complete disclaimer.
- **GitHub Actions runtime compatibility:** replace all seven `actions/upload-artifact` v4 references that targeted deprecated Node.js 20 across CI, Release Gate and tagged-release workflows with the immutable Node.js 24-compatible v7.0.2 release pin.

### Fixed

- **AppImage license/SBOM verification:** pin Syft output to SPDX 2.3 and CycloneDX 1.6, verify and hash the `ca-certificates` post-install hook, preserve native package ownership across flattened ELF libraries, reconcile Python wheel declarations, and stage the pinned GFDL-1.2 fallback when Ubuntu lacks the common-license file.
- **AppImage runtime packaging:** replace appimage-builder and its source patcher with a native AppDir assembled around a custom AppRun and SHA-256-pinned linuxdeploy/appimagetool. Bundle GTK4, Libadwaita, GI typelibs, Python runtime modules, GSettings resources and CA certificates explicitly; validate ELF dependencies and run a finite full-window smoke test.
- **GTK and AppImage warning remediation:** escape the Settings group ampersand for Pango markup, declare Gtk/Adw/Secret GI versions before the system runtime probe imports them, pass the known desktop file and custom AppRun explicitly to linuxdeploy, and omit CPython's static-link-only `python.o` from the runtime AppDir.
- **GTK Scan controls:** use standard `Gtk.Button` widgets inside `Adw.PreferencesGroup`, avoiding unsupported Libadwaita preference-row parentage.
- **Quarantine race and restore hardening (PR #30):** encrypt a stable regular-file snapshot, detach only the verified inode through a pinned directory descriptor, preserve concurrent pathname replacements, and restore through component-pinned no-follow directory descriptors. Bound authenticated record geometry and payload sizes, reject malformed metadata, and skip corrupt records during listing.
- **Quarantine key integrity (PR #30):** distinguish a missing Secret Service key from a malformed stored key; fail closed on corruption rather than silently rotating the key, and log the owner-only key-file fallback.
- **Third-party database lifecycle (PR #30):** validate source IDs and artifact names, prevent cross-source filename collisions, serialize updates across event loops, block source mutation during updates, roll back cancelled updates, preserve recovery backups on rollback failure, and remove partial downloads.
- **Shutdown cleanup (PR #30):** cancel tracked scans safely across stopped worker loops and always close the CLI VirusTotal upload service.
- **USB lifecycle and mount validation:** require an actual mount backed by removable/USB block-device identity beneath an allowed root; track background scan tasks, cancel them on unmount/shutdown, and prevent ordinary directories from being treated as removable devices.
- **Realtime lifecycle and filesystem confinement:** recreate the scan orchestrator on each start, fail startup when configured directories or recursive watches cannot be registered, and expose watch-registration failures instead of reporting incomplete monitoring as active. Pin configured roots, open event targets relative to root descriptors, reject symlink/path traversal and special files, scan through descriptor-preserving clamd transports, and detect file mutation without pathname fallback.
- **Scheduled scans:** persist the last successful daily run across restarts and retry failed scans rather than recording a failed attempt as completed.
- **Background service integration:** start and stop USB, realtime and scheduler services from the GTK application lifecycle using the application's shared scan runner and history store; apply realtime path changes.
- **Autostart:** reject unsupported host XDG autostart writes from inside Flatpak rather than silently claiming that host autostart was installed.

### Security

- **VirusTotal request isolation:** enforce profile-specific authorization, shared rate/quota controls, bounded retries and cooldowns; reject mismatched report digests and avoid exposing provider response bodies or credentials in logs. Preserve request-time API profile/provenance across scan workflows, coordinate shared lookups and cache I/O across event loops/processes, bound resolver shutdown, apply Public-profile pacing (15.1 seconds), and keep Public network lookups blocked until written terms/product-eligibility authorization is recorded.
- **Evidence separation:** keep remote intelligence metadata distinct from the authoritative ClamAV scan verdict.
- **Flatpak credentials:** grant the Secret Service D-Bus name in both manifests; Secret Service availability checks now exercise the D-Bus operation and remain fail-closed.

## [1.0.1] — 2026-10-24

Security and desktop update. Published on GitHub on 2026-10-24 from tag `v1.0.1` (tagged commit `32c9ca62b7b64854e89fbab29ae6311b3678cbf4`). The release description states that the tag followed desktop validation and branch promotion. The checked-in D4 session record remains pending, so the repository does not currently retain the corresponding manual-test evidence. Release checklist:
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
