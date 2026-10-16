# Flatpak packaging

Two manifests are kept side by side on purpose:

| File | Source | Use |
|---|---|---|
| `io.github.clamguardian.ClamGuardian.yml` | wheel sources (offline build) + `type: git` pinned to the `v1.0.0` tag | Release and Flathub submission: reproducible, no moving branch |
| `io.github.clamguardian.ClamGuardian.local.yml` | wheel sources (offline build) + `type: dir`, `path: ../..` | Development: builds the current working tree |

Both manifests target `org.gnome.Platform//51` (runtime target concordato per Flathub; GNOME 46 è EOL). `org.gnome.Sdk//51` è disponibile su Flathub e viene installato dal workflow di release gate.

The `v1.0.0` tag referenced by the release manifest is created by the 1.0 release
gate (`docs/ROADMAP.md`, Phase 9). When a new release is cut, update `tag` and
add the resulting `commit` so that a moved tag cannot silently change the build.

## What the module installs

`pip3 install --no-build-isolation --no-deps --no-index --prefix=/app .` builds
the wheel from the vendored `hatchling` wheel (no network during build, as
required by Flathub), then `pip3 install --no-index --no-deps --prefix=/app`
installs the runtime wheels (`cryptography`, `aiohttp` + transitive) also
vendored as `type: file` sources with pinned `sha256`. Finally the desktop
entry, the AppStream metainfo and the scalable icon are installed into
`/app/share/{applications,metainfo,icons/hicolor/scalable/apps}`. The wheel
itself ships the same three files through `[tool.hatch.build.targets.wheel.shared-data]`
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
not available). The following items remain open for the release gate:

1. `appstreamcli validate` on the metainfo (the repository test only checks the
   structural invariants it can check without the tool).
2. **Build offline — chiuso**: i manifest usano ora wheel vendute (`hatchling`,
   `cryptography`, `aiohttp` + transitive) con `sha256` pinned, installate con
   `pip3 install --no-index --no-build-isolation`; nessun download da PyPI
   avviene durante i `build-commands`.
3. ClamAV inside the sandbox: `flatpak-spawn --host` reaching a host `clamscan`,
   the clamd socket permissions and the definition paths.
4. Restoring a quarantined file to the host filesystem (`--filesystem=host:ro`
   is read-only; restoring to an arbitrary host path needs a portal or a
   narrower, writable path).
