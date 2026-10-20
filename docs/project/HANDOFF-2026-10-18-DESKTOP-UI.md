# ClamGuardian — Desktop UI Development Handoff

## 1. Date & Purpose

2026-10-18. This handoff freezes the agreed plan for the **complete GTK4/Libadwaita
desktop application** (Phases 1–4), approved by the maintainer but **not yet
implemented**. Implementation starts next session from this document.

The historical M4-era handoff (`archive/CLAMGUARDIAN_HANDOFF.md`) remains as archive.

## 2. Repository State

At handoff creation (2026-10-18):

```text
branch:   feature @ 194167c  (Desktop UI Phase D1 complete: diagnostics + app shell) — clean tree
testing:  76439e5  (Merge PR #12 feature → testing, 2026-10-18 — gate green,
                    artifact ClamGuardian-testing-linux-x86_64.flatpak)
main:     ca887aa  (tag v1.0.0 = annotated tag object 20e598a9 → commit 8ee8a56)
tests:    279 passing (pytest), ruff + mypy green, CI + Release Gate green
```

D4 update (2026-10-19): Phase 4 implemented on the working branch
`cline/q41cvf1r`, on top of `feature` @ `a097265` (the CI Xvfb commit that
followed `194167c`), then fast-forwarded to `feature` @ `44ca472`. Local gate
green; CI run 39187789150 green on Python 3.11/3.12/3.13; Release Gate run
39187789165 green (GTK smoke, AppStream, ClamAV, Flatpak local build). The
release-gate inline smoke update is attached as
`docs/project/D4-release-gate.patch` (workflow files require a token with
`workflows` permission); that patch is superseded by
`docs/project/release-gate-1.0.1.patch` (same smoke, plus the 1.0.1 artifact
name) — see `docs/project/D4-RELEASE-GATE.md`. The new widget tests already run
under Xvfb in the CI `test` job.

PR #13 update (2026-10-20): merged to `feature` @ `144e89f`. Audit P1/P2 remediation closed (clamd AUD-01/AUD-04, quarantine key AUD-02/AUD-03, CI hardening AUD-05/07/13 applied in `a315082`, RUNTIME-EXPOSURE AUD-06 accepted, intelligence frozen Phase 11). Local verification green: ruff, mypy 42 files, pytest 350 passed / 8 skipped, real clamd EICAR infected exit 1, newline exit 3, pip-audit clean, no listener on 8080/8081/15001.

## 3. Context — Why This Plan Exists

Findings from the 2026-10-18 session audit:

- **GUI shell exists (Phase D1 complete).** `ClamGuardianApp(Adw.Application)` +
  `MainWindow` with `NavigationSplitView` sidebar; Diagnostics page is real.
  Scan / History / Quarantine are `Adw.StatusPage` placeholders (arrive in D2/D3).
  Databases page (`build_database_navigation()`) is embedded. The only pre-existing
  UI code was `clamguardian/ui/database_pages.py` and `clamguardian/ui/controller.py`
  (`ShieldTaskController`) plus their import-safety shims.
- **The `.desktop` launcher is fixed**: `Exec=clamguardian ui` now launches the
  GTK app shell (diagnostics dialog auto-presented when critical dependencies
  are missing). The README's "Desktop app (GTK4)" section still needs to be
  corrected to describe the real pages (Phase D4).
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
- Status: **COMPLETED** — implemented `clamguardian/core/diagnostics.py`,
  `clamguardian/ui/app.py`, `clamguardian/ui/diagnostics_page.py`, CLI
  `doctor [--json]` (exit code 6), `.desktop` → `Exec=clamguardian ui`,
  CI smoke extended to app + diagnostics page under Xvfb, tests
  `tests/test_diagnostics.py` + `tests/test_ui_shims.py`. Gate green
  (ruff/mypy/pytest).

### Phase 2 — Scan page

- Status: **COMPLETED** — implemented `clamguardian/ui/scan_page.py` with
  target chooser (folder/file/home), profile dropdown, Scan/Cancel buttons,
  in-flight banner (indeterminate progress + elapsed timer + threat counter)
  wired to `ShieldTaskController` signals, result card (clean / infected with
  threat `ActionRow` list / error / cancelled), history recording via
  `record_scan`; integrated into `MainWindow` shell and the GTK smoke job in
  `.github/workflows/release-gate.yml`. Gate green (ruff/mypy/pytest).

### Phase 3 — History + Quarantine pages

- **Status: COMPLETED (`5dbd74c`)** — implemented `clamguardian/ui/history_page.py` (status-filter list with limit, detail dialog, purge with `AlertDialog` confirmation) and `clamguardian/ui/quarantine_page.py` (entry list with restore/delete, key management via Secret Service with `0600` file fallback). Plus `tests/test_history_page.py` and `tests/test_quarantine_page.py`. Gate green (ruff/mypy/pytest).

### Phase 4 — Polish + release readiness

- **Status: COMPLETED** — implemented:
  - `clamguardian/core/settings.py` (JSON settings store: default profile,
    notifications, colour scheme; atomic `0600` writes) and
    `clamguardian/ui/settings_page.py` (Settings page + About row);
  - `clamguardian/ui/style.css` + `clamguardian/ui/theme.py` (packaged
    stylesheet, accent/status classes, colour-scheme application);
  - window chrome in `clamguardian/ui/app.py` (`Adw.ToolbarView` +
    `Adw.HeaderBar` for both panes, page title, main menu, `F1`/`Ctrl+Q`),
    `clamguardian/ui/about.py` (`Adw.AboutDialog` with Gtk fallback);
  - `clamguardian/ui/dialogs.py` (single `Adw.AlertDialog`/`MessageDialog`
    compatibility helper) adopted by the shell, Scan and Quarantine pages;
  - `clamguardian/ui/notifications.py` (configurable, content-free scan-completion
    notifications) wired in `MainWindow`;
  - **Quarantine correctness + ingest**: History and Quarantine now populate
    their lists (the D3 `_done` callbacks discarded the results), restore and
    delete wrap the synchronous vault calls, the folder picker uses
    `Gtk.FileDialog` (no GTK3 `run()`), and detected files can be quarantined
    directly from the Scan result threat list;
  - page refresh on navigation (`MainWindow.show_page`), real target in the
    cancelled result, removal of the dead placeholder branch;
  - README, `docs/ROADMAP.md`, this handoff and the desktop validation
    checklist updated; widget tests extended to every page, Settings, the
    stylesheet and About (`tests/test_app_shell.py`, `tests/test_ui_theme.py`,
    run under Xvfb by the CI test job). The equivalent update to the inline
    `gtk-smoke` job is provided as `docs/project/D4-release-gate.patch`: the
    automation token used for this branch cannot modify workflow files, so the
    maintainer applies it with `git apply` (or in a manual workflow commit).
- Gate: ruff + mypy + pytest green locally (headless); GTK widget tests and
  the Xvfb smoke run in CI. No version bump in D4.

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

Phases 1–4 are **COMPLETED** on the D4 working branch (see `git log`; D4 is
committed on top of `a097265`).

1. Verify baseline (branch, SHAs of all tips, clean tree, CI green).
2. Re-read this handoff and `docs/ROADMAP.md` (Desktop UI phase).
3. Run the manual desktop validation in
   `docs/validation/DESKTOP-TEST-D4-2026-10-19.md` (the D4 session record) and
   `DESKTOP-TEST-1.0.md` §§1–3 and 8 (release evidence).
4. Once the validation is recorded, promote the D4 commits from the working
   branch to `feature` with explicit maintainer authorization, then open the
   `feature → testing` promotion PR.
5. Follow the repo working rules (`docs/ROADMAP.md` § Working Rules): no
   commit/push/merge/tag/PR without explicit authorization.

