# CI/CD and release operations

## Continuous integration

Pull requests run Python quality checks, dependency audit, AppStream
validation, real ClamAV checks, GTK construction smoke tests and native
Flatpak/AppImage packaging checks on x86_64 and aarch64.

Flatpak runtime wheels are generated from `uv.lock` on native runners using
Python 3.14 (GNOME Platform 51). The wheelhouse is hash-verified before the
offline Flatpak build.

AppImages are assembled as explicit AppDirs on native Ubuntu 24.04 runners.
The build includes the Python 3.12 runtime, locked application wheels,
PyGObject/pycairo, GTK4/Libadwaita/Secret libraries and typelibs, GSettings
resources, pixbuf loaders and CA certificates. A custom `AppRun` configures
the runtime. `linuxdeploy`, appimagetool and the type2 runtime are SHA-256
verified. The previous appimage-builder patcher is not used.

The GTK smoke test constructs the complete `MainWindow`, navigation pages,
Scan page, settings, stylesheet and About dialog. It exits successfully only
after construction completes; process liveness alone is not accepted.

## Release candidate

A tag matching `vX.Y.Z` starts `.github/workflows/release.yml`. The pipeline:

1. Builds Flatpak and AppImage natively for x86_64 and aarch64.
2. Installs each Flatpak artifact and checks metadata, CLI and GTK construction.
3. Extracts and executes each AppImage, checks its runtime and CLI, and runs
   the same finite GTK construction smoke test.
4. Stops if any one of the four artifact checks fails.
5. Creates a GitHub Release in Draft state with the four artifacts and
   `SHA256SUMS`.

## Single publication approval

Publication is separate from candidate creation. After reviewing the
Draft release on GitHub, a maintainer performs the single approval by using
**Publish release** in the GitHub Releases UI. Before publishing, verify that
the Draft contains exactly the four expected architecture-specific artifacts
and `SHA256SUMS`, and that the checksums validate. No second workflow dispatch
or per-artifact approval is required.

There is no automatic Flathub publication, partial publication or Wheel/sdist
distribution.

## Maintainer checklist

- Update `pyproject.toml`, `clamguardian/__init__.py`, AppStream release
  metadata, CHANGELOG and the Flatpak source tag together for a new version.
- Ensure `tests/test_packaging.py` and the Python test suite pass before
  tagging.
- Confirm both native architecture jobs are green and the Draft has exactly
  four product artifacts plus `SHA256SUMS`.
- Review release notes and checksums before selecting **Publish release** in GitHub.
