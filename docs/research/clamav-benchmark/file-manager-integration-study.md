# File-Manager Integration Study and Proposed Architecture

## 1. Current ClamGuardian state

**VERIFIED at pinned baseline:** `data/io.github.clamguardian.ClamGuardian.desktop` contains the application launcher (`Exec=clamguardian ui`) but no file-manager context action. No Nemo action, Nautilus extension/script, Dolphin service menu, Caja action or Thunar custom-action artifact was found in the pinned tree.

The freedesktop desktop-entry `Actions` key provides launcher quicklists/jumplists; it is not a universal file-manager context-menu API.

## 2. Native integration mechanisms

| File manager | Mechanism | Key behavior | Recommendation |
|---|---|---|---|
| Nemo / Cinnamon | `.nemo_action` | Selection filters, `%F` path list, `%U` URI list, script | First target |
| Nautilus / GNOME Files | Scripts or nautilus-python `MenuProvider` | Selected paths; dynamic menu via extension | First wave after Nemo |
| Dolphin / KDE | KIO service-menu `.desktop` | MIME filters, `%u`/`%U`, directory MIME | First wave |
| Caja / MATE | Caja-Actions / extensions | Actions over selected files | Optional follow-up |
| Thunar / Xfce | Custom Actions | `%f` first item, `%F` all selected items | Optional follow-up |

Primary references: [Nemo Actions](https://github.com/linuxmint/nemo/blob/master/files/usr/share/nemo/action-info.md), [nautilus-python](https://gnome.pages.gitlab.gnome.org/nautilus-python/nautilus-python-overview.html), [Dolphin service menus](https://develop.kde.org/docs/apps/dolphin/service-menus/), [Caja Actions](https://github.com/mate-desktop/caja-actions), [Thunar custom actions](https://docs.xfce.org/xfce/thunar/custom-actions).

## 3. Concrete target architecture

```text
Nemo / Nautilus / Dolphin / Caja / Thunar
                 |
        thin native adapter
                 |
   ClamGuardian desktop-scan request
                 |
   GApplication / single-instance UI
                 |
        ScanPage / controller
                 |
          ScanTaskRunner
                 |
           ClamAVEngine
                 |
       ScanResult + History
                 |
    GTK result / quarantine action
```

Adapters only collect selected paths and invoke ClamGuardian. They must not invoke ClamAV directly or contain scan, profile, parser, quarantine or history logic. One multi-selection should create one scan session/window.

### Proposed invocation contract

Add a dedicated application entry point, provisional name `clamguardian desktop-scan --request-stdin`. The adapter submits a bounded JSON request on stdin: schema version, local path array and optional profile identifier. Forward the request to the single-instance GTK application and existing controller. Do not create a second scan implementation.

The existing `clamguardian scan` CLI accepts one positional PATH; it does not currently provide a multi-path UI request.

### Validation and safety

- Bound request bytes, path count and path length.
- First release accepts local filesystem paths only; reject unsupported remote URIs explicitly.
- Validate paths in Core, preserve argv elements, never interpolate paths into shell source.
- Define symlink, special-file, mount-boundary and replacement-during-scan policy.
- Re-check file identity/access at scan time; selection is not a stable authorization token.
- Keep existing profile and filesystem safety policy.

## 4. Implementation phases

### FM-1 — Nemo MVP (P2 proposal)
- User-level `.nemo_action` for multi-selection and directory selection.
- One host-side launcher/CLI invocation; no shell concatenation.
- Submit one request to existing GTK controller.
- Reuse progress, cancellation, result and quarantine UI.
- Idempotent installer/uninstaller and exact installed-file documentation.

### FM-2 — Nautilus and Dolphin (P2 proposal)
- Nautilus: start with script; add Python `MenuProvider` only if dynamic menus are required.
- Dolphin: KIO service menu with file and directory MIME support.
- Both use the same request contract.

### FM-3 — Caja and Thunar
Optional, after request API and packaging/uninstall behavior are stable.

## 5. Flatpak/native packaging

The pinned Flatpak manifest uses host integration for ClamAV and host read-only filesystem access. That does not authorize the sandbox to write host file-manager extension directories.

Native packages may install integration files. Flatpak users should run an explicit host-side user installer or install a companion package. The installer must be user-scoped, idempotent, verify app ID/command and support uninstall. Do not add broad writable host filesystem permissions.

## 6. Required test matrix

Single/multiple files, directories, mixed selections, spaces, quotes, Unicode, leading hyphens, newline/control characters, symlinks, broken links, unreadable/special files, remote URIs, removable/unmounted volumes, app already running, app absent, cancellation, notification failure, Flatpak/native launch, uninstall and stale extension cache.

Validate Nemo first on Cinnamon. Do not infer other file managers' behavior from the shared request contract alone.

**Decision — PROPOSED:** Nemo-first thin adapter plus one ClamGuardian-owned multi-path UI request. No implementation is included in this research branch.

## 7. Review corrections — process dispatch and selection contract

### 7.1 Exact Nemo MVP action

Install a user-scoped action at:

`~/.local/share/nemo/actions/clamguardian.nemo_action`

Proposed action file:

```ini
[Nemo Action]
Name=Scan with ClamGuardian
Comment=Scan the selected local files with ClamGuardian
Exec=clamguardian desktop-scan %F
Icon-Name=io.github.clamguardian.ClamGuardian
Selection=notnone
Extensions=any;
Quote=double
Terminal=false
```

Nemo's `%F` token expands to the selected local paths; `Quote=double` asks Nemo to quote each selected path as an individual argument. Do not put `%F` inside an additional quoted shell string (for example, do not use `Exec=... "%F"`). The command must receive an argv vector and must not evaluate a shell program or concatenate selected paths into shell source. The adapter/CLI validates each argument and rejects unsupported URI inputs. The official Nemo action reference documents the user action directory, `%F`, `Selection`, `Extensions` and `Quote`: https://github.com/linuxmint/nemo/blob/master/files/usr/share/nemo/action-info.md.

Uninstall is the inverse operation: remove only this action file and refresh/restart Nemo if its action cache requires it. The installer must not overwrite unrelated Nemo actions. Native packages may ship a system action; Flatpak must not write this host file from inside the sandbox.

### 7.2 Single-instance forwarding

**VERIFIED at the pinned baseline:** `ClamGuardianApp` is an `Adw.Application` with application ID `io.github.clamguardian.ClamGuardian`, but the reviewed implementation does not define a command-line request handler (`HANDLES_COMMAND_LINE` / `do_command_line`) or an equivalent desktop-scan request API. Its current activation path presents the one window; it does not accept a batch of paths from a second process.

**PROPOSED contract:** implement the `desktop-scan` CLI subcommand as a thin request adapter. It validates and bounds argv paths, then starts/contacts the existing `GApplication` using command-line handling. Set up the application for `HANDLES_COMMAND_LINE` and handle the request in the primary instance. GApplication's command-line forwarding is the single-instance boundary; do not invent a second scan daemon or launch a second independent GTK process. The primary instance activates/presents the existing window and dispatches the request to its existing controller/runner.

The forwarded request should have an explicit versioned internal representation: request version, ordered local path array, optional profile identifier and request origin. Define hard limits for total request bytes, number of paths and bytes per path before implementation; reject over-limit requests with a visible actionable error. Preserve argv element boundaries, including spaces, quotes, Unicode and leading hyphens. Newline/control-character paths must be rejected by the existing core safety rules. No shell expansion, eval, command-string interpolation or implicit remote URI conversion.

If the application is not running, the same command-line handler must initialize the normal app/window and then dispatch the request. If it is already running, GApplication must forward the request to that instance. A failed dispatch must return a nonzero CLI result and must not silently drop the selected paths.

### 7.3 Multi-selection and history semantics

**VERIFIED at the pinned baseline:** `ScanPage`, `ShieldTaskController.scan()` and `ScanTaskRunner.submit()` each accept one `Path`. The current history flow records one `ScanResult`; there is no existing multi-path UI request or batch-result contract.

**PROPOSED semantics:** one file-manager selection creates one visible batch session, not N unrelated windows. Keep one result per target (including per-target ERROR/CANCELLED states), with an aggregate summary and batch identifier. Preserve the original selection order for presentation. Use the existing runner's concurrency bound; cancellation stops queued work and requests cancellation of active work while retaining completed per-target results. Persist the batch relationship without flattening away individual target outcomes. Define behavior for partial failure, duplicate paths, overlapping directory/file selections, inaccessible paths and a path disappearing or being replaced after selection before implementing the UI.

The current single-path controller/runner APIs must be extended or wrapped by a dedicated batch coordinator; do not bypass the shared engine, profile, history or quarantine flows.

### 7.4 Flatpak host installation boundary

The Nemo action is a host-side integration artifact. Flatpak's `flatpak-spawn --host` capability for invoking host ClamAV does not authorize the sandbox to create or modify `~/.local/share/nemo/actions`. Provide a separately invoked host-side user installer/uninstaller (or a companion native package), with explicit user consent, exact file ownership, idempotency and uninstall behavior. Do not add broad writable host filesystem permissions. Installation must fail clearly if the host file manager or executable contract is unavailable.

### 7.5 Required acceptance tests

In addition to the existing matrix, test the actual second-process-to-primary-instance route with the app both stopped and already running; one and multiple selections; per-path result/history association; cancellation with queued and active paths; over-limit request rejection; malformed request rejection; and dispatch failure. Test Nemo's actual `%F` + `Quote=double` argv behavior on the target Cinnamon/Nemo version with spaces, quotes, Unicode, leading hyphens and newline/control characters. These host tests remain **BLOCKED** until run on a real Nemo host; source design alone is not a pass.
