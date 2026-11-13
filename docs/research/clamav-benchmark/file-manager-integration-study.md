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
