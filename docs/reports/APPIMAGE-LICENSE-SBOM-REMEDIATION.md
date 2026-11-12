# AppImage License & SBOM Remediation — Execution Report

**Status: IMPLEMENTED ON PR / CI AND RELEASE GATE GREEN / NOT RELEASE-READY**  
**Target:** PR #38, branch `ci/node24-actions` → `feature`  
**CI-verified implementation and test head:** `cf2211542cbb9081fc8777c403e45a64ecbefa8f`.  
**CI:** [run 43318778488](https://github.com/D3M-Sudo/ClamGuardian/actions/runs/43318778488) — **success** (9/9 jobs).  
**Release Gate:** [run 43318778337](https://github.com/D3M-Sudo/ClamGuardian/actions/runs/43318778337) — **success**; all applicable checks passed.

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
- Semantic SPDX license-expression validation against the pinned SPDX License List, including exception identifiers, LicenseRef extracted-text requirements, and the rule that `NONE`/`NOASSERTION` cannot be combined with `OR` or `WITH` (while `AND` remains allowed), and valid `LicenseRef` use as a `WITH` left operand.
- Official SPDX 2.3 and CycloneDX 1.6 JSON-schema validation using pinned upstream schema refs and Git blob IDs.
- A tested release assembler that fails closed on missing/duplicate artifacts, packages per-architecture SBOM/license evidence archives, and verifies release-level SHA-256 checksums.
- Extracted-AppImage verification for architecture, CLI, GTK construction, license tree, native/runtime provenance, SBOM contents, semantic-validation report and final artifact digest.
- A dedicated fail-closed SBOM report validator checks both semantic validation results and all four expected schema-validation documents during extracted-artifact testing.
- CI and release-gate integration, artifact upload, README, CHANGELOG and this evidence report.

## Remote verification results

| Check | Result |
|---|---|
| Ruff `ruff check .` | **Passed** |
| Mypy `mypy clamguardian` | **Passed** |
| Pytest, Python 3.11 | **587 passed, 9 skipped** |
| Pytest, Python 3.12 | **585 passed, 9 skipped** |
| Pytest, Python 3.13 | **585 passed, 9 skipped** |
| Runtime Python 3.14 headless check | **Passed** |
| Pinned dependency audit | **Passed** |
| Native Flatpak x86_64 | **Passed** |
| Native Flatpak aarch64 | **Passed** |
| Native AppImage x86_64 | **Passed** |
| Native AppImage aarch64 | **Passed** |
| Release Gate: preflight, GTK smoke, AppStream, Flatpak local build, real ClamAV scan | **Passed** |

The nine pytest skips in each Python matrix are existing headless/optional-dependency skips. The build-time AppImage pipeline separately installs and exercises the GTK runtime and validates SPDX expressions against the pinned SPDX License List, LicenseRef text requirements, CycloneDX declarations, and the official JSON schemas.

### Native AppImage evidence

Both native architectures completed the extracted-artifact test successfully:

- **x86_64:** 117 bundled Debian package copyright records collected; seven Type 2 runtime license documents fetched and verified; four SBOM documents passed SPDX/CycloneDX semantic and JSON-schema validation; GTK smoke passed; final artifact digest verified as `d94ba52e9b2f1b159d23a650839fda20c0dbc3ec1180398073d886eb2f78d3fb`.
- **aarch64:** 117 bundled Debian package copyright records collected; seven Type 2 runtime license documents fetched and verified; four SBOM documents passed SPDX/CycloneDX semantic and JSON-schema validation; GTK smoke passed; final artifact digest verified as `c228f2072c7302d72af0048b12b6041f482fca491641996488cef45f46cf8d36`.

The artifact test reports passed architecture, runtime, licenses, SBOM, CLI and GTK construction checks for both builds.

## SBOM license coverage — remaining limitation

The actual x86_64 and aarch64 aggregate SPDX SBOMs each contain **142 package records; 110 have `licenseDeclared: NOASSERTION`**. This is a real coverage gap, not a schema-validation failure.

The 13 Python wheel entries are no longer left as `NOASSERTION` in the curated inventory: their declared expressions are now aligned with Syft's extracted wheel metadata and reconciled against SPDX and CycloneDX. These are metadata-derived declarations, not independent legal determinations.

The native inventory has 117 bundled Debian package records: 12 have a normalized package-level SPDX expression and 105 remain `NOASSERTION`. The aggregate SPDX total is 110 `NOASSERTION` records: the 105 native package records plus five AppDir/Syft records. The same counts were independently observed in x86_64 and aarch64 artifacts. Their copyright documents are present in the AppImage, but the collector deliberately does not invent a single package-level SPDX expression when the Debian copyright data is absent, ambiguous, multi-stanza or outside its supported normalization rules. The remaining records retain their full copyright documents and parsed file-level declarations where DEP-5 data is available. They need a separate evidence-backed classification pass before complete package-level license coverage can be claimed.

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


## Follow-up audit — DEP-5 parser scope (2026-11-13)

The post-merge follow-up identified that the original native-license collector aggregated the
first line of every `Files` paragraph and could treat identical file-scoped declarations as
a package-wide license conclusion. DEP-5 distinguishes the package header, `Files` paragraphs,
and stand-alone `License` paragraphs; their declarations are not interchangeable.

The follow-up parser now applies these conservative rules:

- An explicit `License` field in a valid DEP-5 header is treated as the package-level declaration.
- Without a header declaration, a package-level conclusion requires a `Files: *` catch-all
  and identical normalized expressions across all `Files` paragraphs.
- Partial file coverage, mixed expressions, unsupported syntax, and non-DEP-5 documents
  remain `NOASSERTION`.
- File-level evidence includes only `Files` paragraphs; header declarations and stand-alone
  license-text paragraphs are excluded from the file evidence list.

Regression tests cover header scope, partial file coverage, and exclusion of non-file paragraphs.
The tests have been added to the branch; execution is pending CI verification. This change does
not claim legal compliance and does not change any license declaration without supporting evidence.


## Block B follow-up — runtime provenance and LGPL source evidence (2026-11-13)

Implementation is being carried on PR #39, branch `fix/appimage-license-sbom-followup`.
This section supersedes the earlier open findings only where the evidence below
explicitly resolves them. CI verification for this follow-up is pending.

### Embedded CPython / libmpdec

- The bundled CPython package is `libpython3.12-stdlib` version
  `3.12.3-1ubuntu0.17`; its `_decimal` extension is present in the AppDir.
- CPython tag `v3.12.3` declares `MPD_VERSION 2.5.1` in
  `Modules/_decimal/libmpdec/mpdecimal.h`.
- The Debian copyright file contains a file-scoped Stefan Krah notice for
  `Modules/_decimal/libmpdec/*`. The original copyright text is preserved.
- The collector now recognizes BSD-2-Clause only when the notice includes
  both source and binary redistribution conditions and the full disclaimer.
  An incomplete or materially different notice remains `NOASSERTION`.
- The CPython source header establishes the embedded upstream version; the
  Debian copyright notice remains the packaged license evidence. The component
  is represented in the SBOM with partial verification status.

### Type 2 runtime inventory corrections

The inventory schema now distinguishes requested/identified binary package,
source package, upstream version and exact Alpine APK revision. Missing
historical package database records remain null rather than being inferred.

- **zstd:** version corrected to 1.5.6, based on the packaged runtime binary
  evidence; Alpine 3.21 source metadata is consistent with that version. The
  staged license text now comes from the v1.5.6 source tag.
- **zlib:** upstream version 1.3.1 retained; source provenance corrected to
  Alpine 3.21's zlib APKBUILD. The exact installed APK revision is unknown.
- **musl:** upstream version 1.2.5 is supported by Alpine 3.21 source metadata;
  exact installed APK revision remains unknown.
- **mimalloc:** the upstream Dockerfile requests `mimalloc-dev`, and the
  runtime Makefile statically links `-lmimalloc`. The exact selected provider
  and installed APK revision were not retained; version is therefore null and
  unknown. Alpine 3.21's `mimalloc2-dev` 2.1.7 source is included only as a
  candidate in the source bundle, not asserted as the linked version.

### libfuse LGPL source/relink package

The AppImage build now creates an architecture-specific source/relink evidence
archive containing:

- the AppImage Type 2 runtime source at pinned commit
  `dd6cebedcbddde9c82f89b011e8e1d40b6e43868`;
- libfuse 3.15.0 source archive, SHA-256 verified, and the exact
  `mount.c.diff` patch from that runtime commit;
- squashfuse 0.5.2 source archive, SHA-256 verified;
- source snapshots and upstream Alpine 3.21 APKBUILD inputs for zstd 1.5.6,
  zlib 1.3.1, musl 1.2.5 and candidate mimalloc 2.1.7, verified against the
  APKBUILD source checksums;
- the runtime Makefile, Dockerfile, upstream dependency installation script,
  source manifest, relink notes and SHA-256 manifest.

The archive is included in CI AppImage artifacts and the release SBOM evidence
archive. Its documentation explicitly says it is **not a legal-compliance
conclusion**: the historical mimalloc provider/version and installed APK
revision are not proven, and practical relinkability still requires review.
The LGPL-2.1 §6 clearance therefore remains blocked pending independent
engineering/legal assessment and confirmation that the supplied source set is
sufficient to rebuild and relink the published runtime.

### Regression coverage and verification

New tests cover the exact libmpdec two-condition notice, rejection of an
incomplete notice, unknown mimalloc version semantics, zstd version evidence,
and source-bundle integration into build/release evidence. CI has not yet
provided a fresh result for this follow-up; no pass is claimed here.
