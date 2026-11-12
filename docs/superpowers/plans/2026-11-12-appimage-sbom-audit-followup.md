# AppImage SBOM Audit Follow-up — Implementation Plan

> **Execution:** progressive task-scoped commits and pushes on `ci/node24-actions`; use CI as the authoritative test runner because this execution environment has no direct GitHub network access.
>
> **Parent plan/spec:** `docs/superpowers/plans/2026-11-12-appimage-license-sbom.md` and `docs/superpowers/specs/2026-11-12-appimage-license-sbom-design.md`.

**Goal:** Close the independent audit findings that can be resolved with reproducible engineering evidence, while keeping unresolved licensing facts explicitly unknown and preventing release-readiness claims unsupported by evidence.

**Architecture:** Validate SPDX expressions against a pinned official SPDX License List and exception list in addition to JSON schemas. Keep SPDX LicenseRefs backed by actual extracted license text; represent custom CycloneDX licenses as named license objects with attached text. Include architecture-specific SBOM evidence in the eventual Draft release assets. Preserve the native package and Type 2 runtime evidence boundaries.

**Tech Stack:** Python 3.12, pytest, JSON Schema, SPDX License List 3.29.0, SPDX 2.3, CycloneDX 1.6, Bash, GitHub Actions.

## Global Constraints

- Modify only `ci/node24-actions`; PR #38 continues to target `feature`.
- Do not merge, tag, publish, or modify `feature`.
- Never convert missing or ambiguous license/version evidence into an asserted fact.
- SPDX identifiers must be canonical IDs from the pinned SPDX License List; exceptions must come from its exception list.
- Every SPDX `LicenseRef` must have a matching `hasExtractedLicensingInfos` entry with actual license text, not `NOASSERTION`.
- Keep x86_64 and aarch64 SBOMs and artifact hashes separate.
- Preserve the full native copyright documents; package-level `NOASSERTION` remains valid when the evidence does not support a single package-level expression.
- Every implementation task follows RED → GREEN, then a scoped commit and push.
- PR #38 remains open and Draft.

## Review Focus

- A valid SPDX expression contains a deprecated or custom license identifier that is not in the pinned list.
- A `LicenseRef` is declared but has missing, placeholder, or empty extracted text.
- A package has several file-level license stanzas; aggregation must not turn them into a false single package-level license.
- CycloneDX custom license data must remain schema-valid and retain its source text.
- Release assembly must fail if either architecture's required SBOM evidence is absent or ambiguous.

---

### Task 1: Semantic SPDX and CycloneDX license validation

**Files:**
- Modify: `packaging/appimage/install-sbom-validator.sh`
- Modify: `packaging/appimage/validate-sbom.py`
- Modify: `packaging/appimage/license_inventory.py`
- Modify: `packaging/appimage/collect-licenses.py`
- Modify: `packaging/appimage/generate-sbom.py`
- Modify: `packaging/appimage/build-appimage.sh`
- Test: `tests/test_appimage_licenses.py`

**Interfaces:**
- The validator consumes pinned SPDX 3.29.0 `licenses.json` and `exceptions.json`.
- A shared expression parser accepts the valid license-ID set, exception-ID set, and the document's extracted LicenseRef map.
- The parser rejects unknown/non-canonical IDs, malformed expressions, invalid WITH operands, and LicenseRefs without non-placeholder text.
- Custom Debian license names remain LicenseRefs with text extracted from their corresponding Debian copyright license stanza. Do not map them to an SPDX license based on name similarity.
- Known SPDX IDs with case-only differences are normalized to their canonical spelling only when the identifier matches case-insensitively and uniquely.

- [ ] Add regression tests for invalid identifiers `bsd-3-snowball` and `hylafax`, non-canonical `x11`, unknown IDs, malformed expressions, valid exceptions, and LicenseRefs with `NOASSERTION` text.
- [ ] Run the focused CI test and confirm RED.
- [ ] Pin and verify the SPDX 3.29.0 license and exception data using immutable upstream commit/blob hashes.
- [ ] Implement semantic expression validation for both inventories and all SPDX documents.
- [ ] Normalize only evidence-backed aliases; preserve custom licenses as LicenseRefs with extracted text.
- [ ] Emit custom CycloneDX licenses as name/text objects and validate against the pinned 1.6 schema.
- [ ] Run focused tests and the full Python test suite through CI; confirm GREEN.

### Task 2: Native package license evidence precision

**Files:**
- Modify: `packaging/appimage/collect-licenses.py`
- Modify: `packaging/appimage/generate-sbom.py`
- Modify: `packaging/appimage/verify-sbom.py`
- Modify: `packaging/appimage/licenses/components.json`
- Test: `tests/test_appimage_licenses.py`

- [ ] Add tests for DEP-5 multi-stanza files, non-DEP-5 copyright documents, custom license text extraction, and packages with more than one file-level license.
- [ ] Run focused CI tests and confirm RED.
- [ ] Parse supported Debian DEP-5 license stanzas without assuming the first stanza describes every file in the package.
- [ ] Preserve separate file-level license evidence when multiple licenses are present; do not invent a package-level AND/OR expression.
- [ ] Keep package-level `NOASSERTION` where the package-level assertion cannot be established; emit a machine-readable unresolved inventory with package, evidence path, and reason.
- [ ] Reconcile native inventory, SPDX and CycloneDX without silently dropping packages or copyright evidence.
- [ ] Run focused and full test suites through CI; confirm GREEN.

### Task 3: Release SBOM distribution

**Files:**
- Modify: `.github/workflows/release.yml`
- Modify: `tests/test_appimage_licenses.py`
- Modify: `packaging/appimage/README.md`

- [ ] Add workflow-contract tests proving release assembly expects exactly one evidence set for each architecture.
- [ ] Run focused CI test and confirm RED.
- [ ] Copy the four architecture-specific SBOM documents, artifact SHA-256 manifests, schema-validation reports, and relevant license inventories into the release asset directory.
- [ ] Include all evidence files in the Draft release upload and in the release checksum manifest.
- [ ] Fail closed on missing or duplicate evidence files.
- [ ] Run workflow and packaging tests through CI; confirm GREEN. Do not create a tag or release.

### Task 4: Provenance limitations and final evidence report

**Files:**
- Modify: `packaging/appimage/collect-licenses.py` only where a concrete provenance defect is reproduced.
- Modify: `packaging/appimage/licenses/runtime-type2.json` only when immutable upstream evidence proves an exact version.
- Modify: `docs/reports/APPIMAGE-LICENSE-SBOM-REMEDIATION.md`
- Modify: `packaging/appimage/README.md`
- Modify: `CHANGELOG.md`
- Modify: PR #38 description after final CI evidence is available.

- [ ] Add tests proving CA bundle provenance distinguishes package ownership, maintainer-script content, and actual generation evidence.
- [ ] Confirm RED for any reproduced provenance defect.
- [ ] Record exact runtime package versions only if the upstream runtime build provides immutable installed-package evidence; otherwise set version to unknown and retain the gap.
- [ ] Keep libmpdec version unknown unless the embedded build evidence establishes it.
- [ ] Document the libfuse static-link facts and the remaining legal/engineering assessment separately; do not claim legal compliance.
- [ ] Refresh report head SHA, CI run IDs, artifact hashes, package/license counts, unresolved items, and release-readiness verdict from the final runs.
- [ ] Refresh PR description to remove stale commit/run references.
- [ ] Run Ruff, mypy, changelog validation, shell syntax, full pytest, native AppImage x86_64/aarch64, and Release Gate CI.
- [ ] Keep PR #38 open and Draft; no merge, tag, release, or publication.

## Commit strategy

Each task is committed and pushed separately after its RED → GREEN verification. Every push uses a compare-and-swap branch update against the previously verified head SHA. Stop if the remote branch moves unexpectedly; never force-push.

## Completion contract

Semantic SPDX validation passes for both architectures; all emitted LicenseRefs have real text; SBOMs remain schema-valid; native unknowns are accurately represented rather than guessed; release assembly contains both architecture evidence sets; the report and PR description match the final verified head and CI; no Critical or Important finding remains unaddressed. PR #38 stays open and Draft.
