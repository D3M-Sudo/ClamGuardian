# AppImage License & SBOM Remediation — Execution Report

**Status: IMPLEMENTED ON PR / CI GREEN / NOT RELEASE-READY**  
**Target:** PR #38, branch `ci/node24-actions` → `feature`  
**CI-verified PR head:** `e2f0214b63c55fe1dd44a4190efca42ecf348699`. This revision includes the pinned GFDL-1.2 fallback and common-license reference normalization.  
**CI:** [run 43290602327](https://github.com/D3M-Sudo/ClamGuardian/actions/runs/43290602327) — **success**  
**Release Gate:** [run 43290602380](https://github.com/D3M-Sudo/ClamGuardian/actions/runs/43290602380) — **success**

## Implementation delivered

The remediation is committed to the remote PR branch. The implementation includes:

- Complete project GPL-3.0-or-later license text and separate project copyright notice.
- Curated AppDir and Type 2 runtime component inventories.
- Deterministic license staging and runtime license retrieval with pinned upstream Git blob verification. Ubuntu's missing GFDL-1.2 common-license file is covered by an exact bundled copy with SHA-256 verification; trailing punctuation is normalized when resolving Debian common-license references.
- Native Debian package provenance collection based on files actually present in the AppDir, installed package/source versions and copied copyright documents.
- Generated CA-bundle provenance: when `ca-certificates.crt` is not dpkg-listed, the collector requires the actual `ca-certificates.postinst` file, verifies that it invokes `update-ca-certificates`, and records the maintainer-script SHA-256 in `native-packages.json`.
- Provenance matching for ELF libraries flattened by linuxdeploy into `AppDir/usr/lib/`; matching is restricted to unique system multiarch dpkg paths so unrelated copies shipped by browser packages are not misattributed.
- Syft-generated AppDir SPDX 2.3 and CycloneDX 1.6 SBOMs, aggregate SBOMs with Type 2 runtime components, and detached artifact SHA-256 manifests.
- Curated Python wheel license declarations aligned with the expressions detected by Syft. Explicit CycloneDX name aliases for two Syft `LicenseRef` entries and normalization of redundant outer parentheses are covered by tests and checked against both SBOM formats.
- Official SPDX 2.3 and CycloneDX 1.6 schema validation using pinned upstream schema refs and Git blob IDs.
- Extracted-AppImage verification for architecture, CLI, GTK construction, license tree, native/runtime provenance, SBOM contents and final artifact digest.
- CI and release-gate integration, artifact upload, README, CHANGELOG and this evidence report.

## Remote verification results

| Check | Result |
|---|---|
| Ruff `ruff check .` | **Passed** |
| Mypy `mypy clamguardian` | **Passed** |
| Pytest, Python 3.11 | **562 passed, 9 skipped** |
| Pytest, Python 3.12 | **562 passed, 9 skipped** |
| Pytest, Python 3.13 | **562 passed, 9 skipped** |
| Runtime Python 3.14 headless check | **Passed** |
| Pinned dependency audit | **Passed** |
| Native Flatpak x86_64 | **Passed** |
| Native Flatpak aarch64 | **Passed** |
| Native AppImage x86_64 | **Passed** |
| Native AppImage aarch64 | **Passed** |
| Release Gate: preflight, GTK smoke, AppStream, Flatpak local build, real ClamAV scan | **Passed** |

The nine pytest skips in each Python matrix are existing headless/optional-dependency skips. The build-time AppImage pipeline separately installs and exercises the GTK runtime and validates the official SBOM schemas.

### Native AppImage evidence

Both native architectures completed the extracted-artifact test successfully:

- **x86_64:** 117 bundled Debian package copyright records collected; seven Type 2 runtime license documents fetched and verified; four SBOM documents validated against official schemas; GTK smoke passed; final artifact digest verified as `249b938cf5fd800a912b051728ad5ac5126351b1fb9c526cc9335e29aaa221c1`.
- **aarch64:** 117 bundled Debian package copyright records collected; seven Type 2 runtime license documents fetched and verified; four SBOM documents validated against official schemas; GTK smoke passed; final artifact digest verified as `6a672738e3fb5cae9eeb66c96b2d0be48d9d7f2ae8ebc8869fe8d4eeffce2c97`.

The artifact test reports passed architecture, runtime, licenses, SBOM, CLI and GTK construction checks for both builds.

## SBOM license coverage — remaining limitation

The actual x86_64 and aarch64 aggregate SPDX SBOMs each contain **142 package records; 108 have `licenseDeclared: NOASSERTION`**. This is a real coverage gap, not a schema-validation failure.

The 13 Python wheel entries are no longer left as `NOASSERTION` in the curated inventory: their declared expressions are now aligned with Syft's extracted wheel metadata and reconciled against SPDX and CycloneDX. These are metadata-derived declarations, not independent legal determinations.

The remaining 108 unknown declarations include many native/system package records. Their copyright documents are present in the AppImage, but the collector deliberately does not invent a single package-level SPDX expression when the Debian copyright data is absent, ambiguous, multi-stanza or outside its supported normalization rules. Those records need a separate evidence-backed classification pass before complete package-level license coverage can be claimed.

## Remaining release-readiness blockers

1. **Native/system license expressions:** resolve the 108 package-level SPDX `NOASSERTION` declarations from authoritative per-package/per-file license evidence, or retain them explicitly as unresolved. Copyright-file presence alone does not establish a single package-level expression.
2. **Type 2 runtime versions:** musl, zstd, zlib and mimalloc candidate versions are marked `declared` from Alpine 3.21 APKBUILD evidence. The runtime build did not retain the exact installed APK database, so these are not verified installed versions.
3. **libmpdec version:** the embedded library version remains unknown. The copyright evidence establishes the relevant `_decimal`/libmpdec notice, not an independently versioned libmpdec component.
4. **LGPL-2.1 / libfuse:** the static-linking implications, including source and relinkability obligations, still require engineering/legal review. Including the license text is not itself proof that every applicable obligation is met.
5. **Second-party review:** obtain a separate engineering/legal review of the x86_64 and aarch64 evidence bundles and the remaining license interpretations. Native CI and this implementation pass's technical review have exercised both artifacts, but a second-party review has not been recorded as complete.

No legal-compliance conclusion is made. The remaining items above are not CI failures; they are evidence and review gaps that prevent calling the remediation release-ready.

## PR state and change control

PR #38 remains **open and Draft**, with base `feature`. All implementation commits are on `ci/node24-actions`. No merge, tag, release or publication was performed, and `feature` was not modified.

This is an engineering execution report, not legal advice.
