# AppImage License & SBOM Remediation — Execution Report

**Status: IMPLEMENTED LOCALLY / NOT RELEASE-READY**
**Target:** PR #38, branch `ci/node24-actions`
**Remote PR head at last check:** `59bec2db722e8b0f04e2c40a398a585f5dcc1b10`
**Local source:** ZIP snapshot without `.git`; changes have not been committed or pushed.

## Implemented in the local worktree

- Added the complete GPL-3.0-or-later license text and project copyright notice.
- Added curated AppDir and Type 2 runtime component inventories.
- Added deterministic staging of project and third-party license documents.
- Added upstream runtime license retrieval with pinned Git blob IDs for the Type 2 runtime, musl, libfuse, squashfuse, zstd, zlib and mimalloc.
- Added a Debian package provenance collector that maps files actually present in AppDir to the runner's dpkg file lists, captures installed package/source versions and stages the corresponding copyright documents.
- Added conservative Debian copyright `License:` parsing. Ambiguous or unsupported expressions remain `NOASSERTION`.
- Added `_decimal`/libmpdec detection. The build requires a copyright stanza identifying both Stefan Krah and the `_decimal`/libmpdec source; the embedded library version remains explicitly unknown unless source evidence establishes it.
- Added Syft AppDir SPDX 2.3 and CycloneDX 1.6 generation, curated runtime/native package aggregation, detached final-artifact SHA-256 manifest and reconciliation checks.
- Added official SPDX 2.3 and CycloneDX 1.6 schema validation using pinned upstream schema refs and Git blob IDs.
- Extended extracted-AppImage tests and CI/release artifact uploads to include license and SBOM evidence.
- Updated AppImage documentation and CHANGELOG.

## Local verification completed

| Check | Result |
|---|---|
| Full pytest suite | **525 passed, 19 skipped** |
| AppDir/runtime inventory validator | Passed |
| CHANGELOG validation | Passed |
| Bash syntax for `packaging/appimage/*.sh` | Passed |
| `AppRun` shell syntax | Passed |
| Python compilation for AppImage scripts | Passed |
| GitHub Actions YAML parsing | Passed |

The 19 skipped tests require GTK/PyGObject and/or a display server unavailable in this environment.

## Evidence still required before declaring R1–R8 complete

1. Run the native x86_64 and aarch64 CI builds and inspect the actual AppImages.
2. Execute the pinned runtime-license downloads and verify all Git blob IDs in CI.
3. Run Syft against each actual AppDir and validate all four generated SBOM documents against the downloaded official schemas.
4. Confirm the package collector on both Ubuntu runner architectures, especially the exact `ca-certificates` copyright and the `_decimal`/libmpdec copyright stanza.
5. Reconcile all 13 Python wheel versions and license metadata against the generated Syft SBOMs; their curated license expressions remain `NOASSERTION` until verified.
6. Alpine 3.21 APKBUILD revisions provide declared candidate versions for musl, zstd, zlib and mimalloc, but the Type 2 runtime build did not retain its exact installed APK database. These versions are therefore marked `declared`, not `verified`.
7. Review the static-linking implications of libfuse's LGPL-2.1 license, including source and relinkability obligations. The presence of the license text alone does not settle those obligations; no legal-compliance conclusion is made here.
8. Perform the independent aarch64 artifact extraction and license/SBOM audit required by R8.
9. Run Ruff and mypy; those executables are not installed in the available work environment.

## Repository/PR status

The available source was an archive without Git metadata. The shell also could not resolve `github.com`, and `gh` is unavailable. Consequently, this report and implementation changes exist only in the local worktree. **PR #38 has not been updated by this work; no commit, push, merge, tag or release was performed.**

The work must remain classified as incomplete until the native CI and unresolved evidence above are satisfied. This report is an engineering status record, not legal advice.
