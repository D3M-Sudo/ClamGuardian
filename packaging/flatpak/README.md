# Flatpak packaging

Two manifests are kept side by side:

| File | Source | Use |
|---|---|---|
| \`io.github.clamguardian.ClamGuardian.yml\` | GNOME 51 runtime, source Git tag pinned to the current package version, plus a native generated wheelhouse | Release builds |
| \`io.github.clamguardian.ClamGuardian.local.yml\` | GNOME 51 runtime and current working tree | CI and development builds |

## Native architecture wheelhouse

The previous manifests embedded x86_64-only binary wheels. The current CI
prepares a wheelhouse separately on each native runner from the checked-in
\`uv.lock\`:

\`\`\`sh
python -m pip install uv==0.9.5
packaging/flatpak/prepare-wheelhouse.sh
\`\`\`

The script exports the locked runtime set without development dependencies,
then runs \`pip download --require-hashes --only-binary=:all:\` using the native
Python 3.14 interpreter. Each downloaded wheel is checked against the hashes
in \`uv.lock\`. The Flatpak build itself installs only from that wheelhouse
with \`--no-index --no-deps\`, so no dependency is fetched from PyPI during
the sandbox build.

The local manifest obtains the generated wheelhouse as part of the working
tree source. The release manifest adds the generated directory as a separate
source at \`packaging/flatpak/wheelhouse\` and obtains application source from
the immutable Git tag. The tag, \`pyproject.toml\` version and AppStream
release version must be updated together before creating a new release tag.

## Offline build and platform

Both manifests target \`org.gnome.Platform//51\` and \`org.gnome.Sdk//51\`.
The runtime wheelhouse is architecture-native: x86_64 builds run on
\`ubuntu-24.04\`; aarch64 builds run on \`ubuntu-24.04-arm\`. No binary wheel is
cross-labelled or reused between architectures.

The application installs its desktop entry, AppStream metainfo and scalable
icon under \`/app/share\`. Runtime dependencies are installed offline into
\`/app\`; the build backend and its dependencies remain separately vendored
and SHA-256 pinned in both manifests.

## finish-args rationale

| Argument | Why |
|---|---|
| \`--socket=fallback-x11\`, \`--socket=wayland\`, \`--device=dri\`, \`--share=ipc\` | GTK4/Libadwaita presentation |
| \`--talk-name=org.freedesktop.Flatpak\` | \`flatpak-spawn --host\` executes host ClamAV tools |
| \`--talk-name=org.freedesktop.secrets\` | Secret Service credentials |
| \`--filesystem=host:ro\` | Read host ClamAV definitions and clamd socket |
| \`--share=network\` | Explicit user-initiated database downloads |
| \`--filesystem=xdg-data/clamguardian:create\` | Quarantine, scan history and database state |

The sandbox permission set is unchanged by the multi-architecture packaging
work. The existing residuals remain: host-side ClamAV integration and
quarantine restore destinations require real-desktop validation.
