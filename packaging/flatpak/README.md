# Flatpak packaging

Two manifests are kept side by side on purpose:

| File | Source | Use |
|---|---|---|
| `io.github.clamguardian.ClamGuardian.yml` | `type: git`, pinned to the `v1.0.0` tag | Release and Flathub submission: reproducible, no moving branch |
| `io.github.clamguardian.ClamGuardian.local.yml` | `type: dir`, `path: ../..` | Development: builds the current working tree |

The `v1.0.0` tag referenced by the release manifest is created by the 1.0 release
gate (`docs/ROADMAP.md`, Phase 9). When a new release is cut, update `tag` and
add the resulting `commit` so that a moved tag cannot silently change the build.

## What the module installs

`pip install --no-deps --prefix=/app .` plus explicit installation of the desktop
entry, the AppStream metainfo and the scalable icon into
`/app/share/{applications,metainfo,icons/hicolor/scalable/apps}`. The wheel itself
ships the same three files through `[tool.hatch.build.targets.wheel.shared-data]`
in `pyproject.toml`.

## finish-args rationale

| Argument | Why |
|---|---|
| `--socket=fallback-x11`, `--socket=wayland`, `--device=dri`, `--share=ipc` | GTK4/Libadwaita presentation |
| `--talk-name=org.freedesktop.Flatpak` | `flatpak-spawn --host` is how `clamscan`/`freshclam` run on the host |
| `--filesystem=host:ro` | read the host ClamAV definitions and reach the clamd UNIX socket |
| `--share=network` | user-initiated third-party database downloads over HTTPS only |
| `--filesystem=xdg-data/clamguardian:create` | quarantine vault, scan history and database state |

## Not verified by the repository

Building and running the Flatpak could not be validated in the remediation
environment (`flatpak-builder`, an ostree repository and a Flatpak runtime were
not available). The following are therefore **open items for the release gate**:

1. `appstreamcli validate` on the metainfo (the repository test only checks the
   structural invariants it can check without the tool).
2. A real `flatpak-builder` run: the build backend (`hatchling`) must be
   available *offline*, which Flathub requires. `pip install .` with build
   isolation would try to download it; the manifest needs either a
   `python3-hatchling` module or a vendored wheel before submission.
3. ClamAV inside the sandbox: `flatpak-spawn --host` reaching a host `clamscan`,
   the clamd socket permissions and the definition paths.
4. Restoring a quarantined file to the host filesystem (`--filesystem=host:ro`
   is read-only; restoring to an arbitrary host path needs a portal or a
   narrower, writable path).
