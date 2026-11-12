# AppImage packaging

AppImages are assembled natively on Ubuntu 24.04 runners for x86_64 and
aarch64. The build no longer uses appimage-builder or patches its internal
Python modules.

## Build contract

1. Export the runtime dependency set from `uv.lock` and download only native
   wheels, verifying every wheel against the lockfile hashes.
2. Install Ubuntu 24.04 Python 3.12, PyGObject/pycairo and GTK runtime packages
   on the native runner.
3. Assemble an explicit AppDir containing the Python standard library,
   locked application wheels, GI typelibs, GTK4/Libadwaita/Secret libraries
   and resources, GSettings schemas, pixbuf loaders and CA certificates.
4. Run SHA-256-pinned `linuxdeploy` against Python and bundled ELF modules.
   Required GTK/Adwaita/Secret libraries and GI typelibs are checked after
   deployment; unresolved ELF dependencies abort the build.
5. Use the maintained custom `AppRun` to configure Python, GI, GIO,
   GSettings, pixbuf loaders and CA certificates.
6. Install the AppStream metadata under the filename expected by appimagetool.
7. Package with SHA-256-pinned appimagetool 1.9.1 and the pinned type2 runtime.
   Test extraction, architecture, desktop/icon/metainfo assets, CLI and complete
   GTK window construction before uploading the artifact.

No x86_64 artifact is relabelled as aarch64. Each architecture is built and
tested on a native runner.

The AppImage bundles userspace Python/GTK/GI libraries and resources but
intentionally relies on the host kernel, glibc baseline, graphics drivers,
display server, D-Bus session, Secret Service daemon and ClamAV installation.
The compatibility baseline is Ubuntu 24.04; older distributions require
separate runtime validation before being listed as supported.

## License and SBOM evidence

The AppImage build stages the complete project GPL-3.0-or-later text and project
copyright into `usr/share/licenses/ClamGuardian`. After native runtime assembly,
`collect-licenses.py` maps bundled files to the runner's dpkg file lists and copies the corresponding package copyright documents. It follows symlink targets and handles libraries flattened by linuxdeploy into `usr/lib` only when their SONAME filename maps uniquely to a system multiarch dpkg file; the source path and detection method are recorded in `native-packages.json`. The generated
`/etc/ssl/certs/ca-certificates.crt` bundle is attributed explicitly to
`ca-certificates` through its `postinst` hook because dpkg does not list this
generated output as a packaged file. Both the generated artifact path and the
maintainer-script provenance are recorded in `native-packages.json`. The build
fails when a bundled Debian package has no readable copyright document. Python wheel license
files remain in their `.dist-info/licenses` directories. The Type 2 runtime's
MIT, musl, libfuse, squashfuse, zstd, zlib and mimalloc license texts are fetched
from immutable upstream refs and checked against pinned Git blob IDs before
being staged. The mimalloc notice is included explicitly because the upstream
runtime Makefile statically links `-lmimalloc` although the runtime's own
`LICENSE` list does not mention it.

Syft is installed at a pinned version and SHA-256 per architecture. It generates
AppDir SPDX 2.3 and CycloneDX 1.6 documents. The curated Type 2 runtime inventory
is added to separate aggregate SBOMs because the runtime executable is outside
the AppDir SquashFS. A detached artifact manifest binds both aggregate SBOMs to
the final AppImage SHA-256 and architecture. SPDX 2.3 and CycloneDX 1.6 output
is validated against the official JSON schemas whose upstream Git blob IDs
and source refs are pinned in `install-sbom-validator.sh`. CI uploads the AppImage and all
license/SBOM evidence together.
