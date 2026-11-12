# AppImage packaging

AppImages are built natively on Ubuntu 24.04 runners for x86_64 and aarch64.
The recipe bundles GTK4, Libadwaita, PyGObject, Secret Service client libraries
and the application's locked Python runtime dependencies.

## Build contract

1. Export runtime dependencies from uv.lock without development packages.
2. Download only wheels compatible with the native Python 3.12 runner, verifying
   every wheel against the lockfile hashes.
3. Compile a small native ELF launcher for the target architecture; it configures the bundled Python/GTK environment and forwards CLI arguments.\n4. Package the Python application and GTK runtime using appimage-builder.
5. Execute CLI smoke checks and start the GTK event loop under Xvfb/DBus.
   The test requires the event loop to remain alive until the bounded timeout.

No x86_64 artifact is relabelled as aarch64. Each architecture is built and
tested on a native runner.

The AppImage includes userspace libraries but relies on the host kernel,
graphics drivers, display/DBus session and ClamAV installation. Hardware
drivers and host ClamAV executables are intentionally not bundled.


## Compatibility baseline

The native AppImages are built on Ubuntu 24.04 and therefore use its glibc
baseline. CI proves execution on the matching Ubuntu 24.04 architecture, not
compatibility with older glibc distributions. Older distributions require
separate runtime validation before being listed as supported. Host graphics
drivers, kernel, display server, D-Bus and ClamAV remain host-provided.
