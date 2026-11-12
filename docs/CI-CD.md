# CI/CD and release operations

## Continuous integration

Pull requests targeting feature run Python quality checks, dependency audit,
AppStream validation, real ClamAV checks, GTK smoke tests and native Flatpak
build/install/launch checks on x86_64 and aarch64.

Flatpak runtime wheels are generated from uv.lock on native runners using
Python 3.14 (GNOME Platform 51). The wheelhouse is hash-verified before the
offline Flatpak build; this replaces the former x86_64-only binary wheel set.

## Release candidate

A tag matching vX.Y.Z starts .github/workflows/release.yml. The pipeline:

1. Builds Flatpak and AppImage natively for x86_64 and aarch64.
2. Installs and starts each Flatpak artifact independently.
3. Executes each AppImage, checks its CLI and starts GTK under Xvfb/DBus.
4. Stops if any one of the four artifact checks fails.
5. Creates a GitHub Release in Draft state with the four artifacts and SHA256SUMS.

A manual workflow_dispatch of the release workflow on a branch can validate
packaging; it builds and tests artifacts but does not create a GitHub Release.

## Single publication approval

Publication is separate from candidate creation. Run Publish release
(.github/workflows/publish-release.yml) manually and enter the exact tag.
That single workflow dispatch is the sole publication approval. The workflow
requires a Draft, verifies all four artifacts and SHA256SUMS, validates every
checksum, and only then changes the Draft to a published GitHub Release.

There is no automatic Flathub publication, partial publication or Wheel/sdist
distribution.

## Maintainer checklist

- Update pyproject.toml, clamguardian/__init__.py, AppStream release metadata,
  CHANGELOG and the Flatpak source tag together for a new version.
- Ensure tests/test_packaging.py passes before tagging.
- Confirm both native architecture jobs are green and the Draft has exactly
  four product artifacts plus SHA256SUMS.
- Review release notes and checksums before running the publication workflow.
