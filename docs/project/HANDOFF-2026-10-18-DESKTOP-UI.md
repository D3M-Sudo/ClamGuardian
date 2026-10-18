# ClamGuardian — Desktop UI Development Handoff

## 1. Date & Purpose

2026-10-18. This handoff freezes the agreed plan for the **complete GTK4/Libadwaita
desktop application** (Phases 1–4), approved by the maintainer but **not yet
implemented**. Implementation starts next session from this document.

The historical M4-era handoff (`archive/CLAMGUARDIAN_HANDOFF.md`) remains as archive.

## 2. Repository State

```text
branch:   feature @ 1eb9335  (Docs: riscrittura README user-first) — clean tree
testing:  76439e5  (Merge PR #12 feature → testing, 2026-10-18 — gate green,
                    artifact ClamGuardian-testing-linux-x86_64.flatpak)
main:     ca887aa  (tag v1.0.0 = annotated tag object 20e598a9 → commit 8ee8a56)
tests:    254 passing (pytest), ruff + mypy green, CI + Release Gate green
```

## 3. Context — Why This Plan Exists

Findings from the 2026-10-18 session audit:

- **No GUI exists.** There is no `Adw.Application`, no main window, no sidebar,
  no Scan/History/Quarantine/Diagnostics pages. The only UI code is
  `clamguardian/ui/database_pages.py` (third-party database pages, exposed via
  `build_database_navigation()`), `clamguardian/ui/controller.py`
  (`ShieldTaskController`, GObject signals over `ScanTaskRunner`) and their
  import-safety shims.
- **The `.desktop` launcher is latently broken**: `Exec=clamguardian` with
  `Terminal=false` invokes the CLI with no subcommand → argparse error, exit 2,
  nothing visible. The README's "Desktop app (GTK4)" section describes pages
  that do not exist in code (to be made real by this plan).
- **Reference app**: `clamui` (linx-systems) — its `src/ui/components_view.py`
  (per-component status rows + per-distro install guides in expanders) and
  `src/ui/database_missing_dialog.py` (`Adw.Window` modal, Libadwaita <1.5
  compatible) are the patterns to adapt for the Diagnostics UI.
- **Visual reference**: Malwarebytes desktop layout (left sidebar with
  Scan / Detection History / Protection / Settings, prominent protection-status
  banner, large scan cards). The screenshot
  `https://media.cybernews.com/images/1024w/2026/06/malwarebytes-scan.png` could
  not be fetched (HTTP 403); the mapping below is based on the known design.

## 4. Core Inventory (UI-ready, verified 2026-10-18)

| Capability | Module | GUI readiness |
|---|---|---|
| Scan with clamd→clamscan fallback, `update_signatures()` (freshclam), `flatpak_host` | `clamguardian/engines/clamav.py` | ready |
| Async orchestration + cancellation | `core/runner.py` + `ui/controller.py` (`ShieldTaskController`) | ready |
| Profiles quick/home/full/custom | `core/profiles.py` (`resolve_profile`, registry) | ready |
| Scan history (async SQLite) | `history/backend.py` (`record_scan`/`list_scans`/`get_scan`/`purge`/`count_scans`) | ready |
| Encrypted quarantine vault | `core/quarantine.py` | library only — **no persistent key management exists anywhere** (CLI has no `quarantine` subcommand either) |
| Third-party signature databases + GTK pages | `databases/` + `ui/database_pages.py` | page exists; needs embedding in the shell |
| VirusTotal client | `intelligence/` (~56 lines) | embryonic; out of scope for MVP |
| Thread→GTK marshalling + headless shim pattern | `ui/database_pages.py` (`run_async`, `_GtkNotAvailable`, `GTK_AVAILABLE`) | reuse everywhere |

Known gaps:

- Engine emits **no incremental progress** (`ScanProgress` model exists in
  `core/base.py` but no callback is wired). MVP shows indeterminate state +
  timer + threat counter; wiring a progress signal is optional Phase 2 scope.
- Quarantine key persistence must be designed (Secret Service/libsecret with a
  `0600` file fallback in app-data), including inside the Flatpak sandbox.

## 5. Approved Plan — Phases 1–4

Guiding constraints for every phase: GTK import-safe/headless (guard
`GTK_AVAILABLE` + shim, keep the suite green without PyGObject), no `shell=True`
(command argument lists only, `flatpak-spawn --host` inside the sandbox),
`run_async` for asyncio→GLib marshalling, ruff/mypy/pytest green + CI smoke
green before each commit to `feature`. Visual style: Malwarebytes layout mapped
to Libadwaita (`Adw.NavigationSplitView` sidebar, `Adw.StatusPage` status
banner with `success`/`warning` CSS classes, `Adw.PreferencesGroup` cards,
`Adw.ActionRow` rows, `Adw.Dialog` details, native dark theme + custom accent
CSS).

### Phase 1 — Foundations + Diagnostics (the maintainer's original request)

- `clamguardian/core/diagnostics.py` (headless): `run_dependency_checks()` →
  `list[CheckResult]` covering `clamscan`, `clamdscan`, `freshclam`, daemon
  `clamd` (running/stopped/not-installed via socket + process probe), signature
  databases present/fresh, Flatpak environment detection. Binary lookup via
  `shutil.which`, or `flatpak-spawn --host which …` in the sandbox. Each result
  carries per-distro `remedy` commands (Debian/Ubuntu, Fedora, Arch).
- CLI `clamguardian doctor [--json]` + dedicated exit code in
  `cli/exit_codes.py`.
- `clamguardian/ui/app.py`: `ClamGuardianApp(Adw.Application)` + `MainWindow`
  with `NavigationSplitView` (Scan, History, Quarantine, Databases,
  Diagnostics), toast overlay, keyboard accelerators; **diagnostics dialog
  auto-presented at startup when critical dependencies are missing**.
- `clamguardian/ui/diagnostics_page.py`: global status banner, one card per
  component (status icon + state), expander with per-distro install commands,
  Recheck button.
- Packaging: new `clamguardian ui` subcommand, `.desktop` updated to
  `Exec=clamguardian ui`, Flatpak `command` aligned.
- CI: extend the GTK smoke job to construct the app + diagnostics page under
  Xvfb.
- Tests: `tests/test_diagnostics.py` (~150 lines, mocked `which`/socket), UI
  shim tests.
- Estimate: ~700–900 lines UI/core + ~250 test lines.

### Phase 2 — Scan page

- `ui/scan_page.py`: protection-status banner, target chooser
  (folder/file/home), profile dropdown, large Scan button, in-flight state
  (indeterminate progress + elapsed timer + threat counter) via
  `ShieldTaskController` signals, Cancel, result card (clean / infected with
  threat `ActionRow` list / error), history recording via `record_scan`.
- Optional: `scan-progress` signal on `ShieldTaskController` if engine progress
  parsing proves practical.
- Estimate: ~300–350 lines + tests.

### Phase 3 — History + Quarantine pages

- `ui/history_page.py`: `list_scans` with status filter and limit, detail
  dialog, purge with `AlertDialog` confirmation.
- `ui/quarantine_page.py`: `list_entries`, restore (destination dialog) and
  delete with confirmation; **key management**: generated on first use, stored
  via Secret Service (libsecret available in the GNOME runtime) with `0600`
  file fallback in app-data; Flatpak sandbox behaviour verified.
- Estimate: ~450–550 lines + tests.

### Phase 4 — Polish + release readiness

- Accent CSS provider + bundled `data/style.css`, About dialog (AppStream
  metainfo exists), optional desktop notifications via portal, light settings
  (default profile).
- README "Desktop app" section corrected to describe the real pages;
  `docs/design/desktop-ui.md` design note; desktop validation checklist
  updated; smoke test extended to all pages; visual validation under Xvfb.
- Estimate: ~200 lines + docs.

Gate per phase: ruff + mypy + pytest green, CI smoke green, commit to `feature`
(none of this runs without the maintainer's go-ahead per session). After Phase
1 the diagnostics window is already usable on a real desktop.

## 6. Malwarebytes → Adwaita Mapping

| Malwarebytes | ClamGuardian (Adwaita) |
|---|---|
| Left sidebar icons+labels | `Adw.NavigationSplitView` + `Adw.NavigationPage` |
| Status banner ("You're protected" / "Action needed") | `Adw.StatusPage` with `success`/`warning` CSS classes |
| Large card with round Scan button | `Adw.PreferencesGroup` card + wide `.suggested-action` button |
| Result card with per-threat rows | `Adw.ActionRow` with status icon |
| Dark friendly theme | native Adwaita dark + accent CSS provider |
| Detail dialogs | `Adw.Dialog` (already used in `database_pages.py`) |

## 7. Next Session Procedure

1. Verify baseline (branch `feature`, SHAs of all tips, clean tree, CI green).
2. Re-read this handoff and `docs/ROADMAP.md` (Desktop UI phase).
3. Start Phase 1 with `core/diagnostics.py` + CLI `doctor` (testable headless
   first), then the app shell + diagnostics page.
4. Follow the repo working rules (`docs/ROADMAP.md` § Working Rules): no
   commit/push/merge/tag/PR without explicit authorization.

