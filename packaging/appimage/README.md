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
6. Package with SHA-256-pinned appimagetool 1.9.1 and the pinned type2 runtime.
   Test extraction, architecture, CLI and complete GTK window construction
   before uploading the artifact.

No x86_64 artifact is relabelled as aarch64. Each architecture is built and
tested on a native runner.

The AppImage bundles userspace Python/GTK/GI libraries and resources but
intentionally relies on the host kernel, glibc baseline, graphics drivers,
display server, D-Bus session, Secret Service daemon and ClamAV installation.
The compatibility baseline is Ubuntu 24.04; older distributions require
separate runtime validation before being listed as supported.
