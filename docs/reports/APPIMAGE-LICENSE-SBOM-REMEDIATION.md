# AppImage License & SBOM Remediation — Execution Report

**Status: IMPLEMENTED ON PR / NATIVE CI GREEN / NOT RELEASE-READY**  
**Target:** PR #38, branch `ci/node24-actions` → `feature`  
**Verified PR head:** `0e31cd3bd6b89c9028fb4dc6d01ab4de496d51cd`  
**CI:** [run 43285081892](https://github.com/D3M-Sudo/ClamGuardian/actions/runs/43285081892) — **success**  
**Release Gate:** [run 43285081896](https://github.com/D3M-Sudo/ClamGuardian/actions/runs/43285081896) — **success**

## Implementation delivered

The remediation is committed to the remote PR branch. The implementation includes:

- Complete project GPL-3.0-or-later license text and separate project copyright notice.
- Curated AppDir and Type 2 runtime component inventories.
- Deterministic license staging and runtime license retrieval with pinned upstream Git blob verification.
- Native Debian package provenance collection based on files actually present in the AppDir, installed package/source versions and copied copyright documents.
- Explicit provenance for the generated `ca-certificates.crt` output through the `ca-certificates.postinst` hook.
- Provenance matching for ELF libraries flattened by linuxdeploy into `AppDir/usr/lib/`; matching is restricted to unique system multiarch dpkg paths so unrelated copies shipped by browser packages are not misattributed.
- Embedded `_decimal`/libmpdec evidence gate. Its version remains unknown because the available package copyright evidence does not establish a separate embedded library version.
- Syft-generated AppDir SPDX 2.3 and CycloneDX 1.6 SBOMs, aggregate SBOMs with Type 2 runtime components, and detached artifact SHA-256 manifests.
- Official SPDX 2.3 and CycloneDX 1.6 schema validation using pinned upstream schema refs and Git blob IDs.
- Extracted-AppImage verification for architecture, CLI, GTK construction, license tree, native/runtime provenance, SBOM contents and final artifact digest.
- CI and release-gate integration, artifact upload, README, CHANGELOG and this evidence report.

## Remote verification results

| Check | Result |
|---|---|
| Ruff `ruff check .` | **Passed** |
| Mypy `mypy clamguardian` | **Passed** |
| Pytest, Python 3.11 | **557 passed, 9 skipped** |
| Pytest, Python 3.12 | **557 passed, 9 skipped** |
| Pytest, Python 3.13 | **557 passed, 9 skipped** |
| Runtime Python 3.14 headless check | **Passed** |
| Pinned dependency audit | **Passed** |
| Native Flatpak x86_64 | **Passed** |
| Native Flatpak aarch64 | **Passed** |
| Native AppImage x86_64 | **Passed** |
| Native AppImage aarch64 | **Passed** |
| Release Gate: preflight, GTK smoke, AppStream, Flatpak local build, real ClamAV scan | **Passed** |

The nine pytest skips in each Python matrix are existing headless/optional-dependency skips; the build-time AppImage pipeline separately installs and exercises the GTK runtime and validates the official SBOM schemas.

### Native AppImage evidence

Both native architectures completed the extracted-artifact test successfully:

- **x86_64:** 117 bundled Debian package copyright records collected; seven Type 2 runtime license documents fetched and verified; four SBOM documents validated against official schemas; GTK smoke passed; final artifact digest verified as `bfc31444b0ebeed3a5b4d5203cb0e606f2d0b7c80a9cfc6579dfd92b2679f7ac`.
- **aarch64:** 117 bundled Debian package copyright records collected; seven Type 2 runtime license documents fetched and verified; four SBOM documents validated against official schemas; GTK smoke passed; final artifact digest verified as `c6e35ed0cc08fb031501e0fbdada3f7f0d1172da9db1d6a66930968f58d197bc`.

The artifact test reports passed architecture, runtime, licenses, SBOM, CLI and GTK construction checks for both builds. This verifies native CI packaging and extraction on both architectures; it is not a substitute for a separate independent review of the resulting evidence.

## Remaining release-readiness blockers

1. **Python wheel license classification:** 13 curated Python wheel entries still use `NOASSERTION` / unknown license status. Reconcile the wheel metadata and notices against the generated Syft records before making a complete license-coverage claim.
2. **Type 2 runtime versions:** musl, zstd, zlib and mimalloc candidate versions are marked `declared` from Alpine 3.21 APKBUILD evidence. The runtime build did not retain the exact installed APK database, so these are not verified installed versions.
3. **libmpdec version:** the embedded library version remains unknown. The copyright evidence establishes the relevant `_decimal`/libmpdec notice, not an independently versioned libmpdec component.
4. **LGPL-2.1 / libfuse:** the static-linking implications, including source and relinkability obligations, still require engineering/legal review. Including the license text is not itself proof that every applicable obligation is met.
5. **Independent review:** perform a separate review of the x86_64 and aarch64 evidence bundles and a final whole-branch review for material omissions. Native CI has exercised both artifacts, but this independent review has not been recorded as complete.

No legal-compliance conclusion is made. The remaining items above are not CI failures; they are evidence and review gaps that prevent calling the remediation release-ready.

## PR state and change control

PR #38 remains **open and Draft**, with base `feature`. All implementation commits are on `ci/node24-actions`. No merge, tag, release or publication was performed, and `feature` was not modified.

This is an engineering execution report, not legal advice.
