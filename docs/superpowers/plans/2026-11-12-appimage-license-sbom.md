# AppImage License & SBOM Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Deliver complete license/copyright evidence and whole-artifact SBOMs for ClamGuardian x86_64 and aarch64 AppImages.

**Architecture:** Keep project/AppDir license payloads and curated package metadata under `packaging/appimage/licenses/`. Generate AppDir SBOMs with pinned Syft, then add a separately evidenced Type 2 runtime inventory to aggregate SPDX and CycloneDX outputs. Validate the extracted final AppImage on native runners.

**Tech Stack:** Bash packaging scripts, Python 3.12, pytest, Syft, SPDX JSON 2.3, CycloneDX JSON 1.6, GitHub Actions native x86_64/aarch64 runners.

**Spec:** `docs/superpowers/specs/2026-11-12-appimage-license-sbom-design.md`

## Global Constraints

- Work only on `ci/node24-actions` in PR #38; target remains `feature`.
- Do not merge, tag, publish, or modify `feature`.
- Preserve native architecture builds and existing pinned AppImage tooling.
- Never infer unverified package versions, license expressions or copyright.
- Keep AppDir SBOM, Type 2 runtime inventory and aggregate SBOM distinct.
- Tests must exercise the extracted AppImage, not only source files.
- Update CHANGELOG and packaging documentation.
- No legal compliance claim without evidence for every material obligation.

## Review Focus

- A package is installed but its copied files originate from a different Debian/Ubuntu binary package than the guessed package name.
- A wheel contains a native extension or vendored library with notices not represented by the top-level wheel metadata.
- Syft reports an AppDir package but misses a static/runtime component outside SquashFS.
- SPDX/CycloneDX aggregation produces duplicate identifiers or invalid license expressions/relationships.
- Aarch64 differs from x86_64 in package version, file layout, runtime hash or available copyright metadata.

---

### Task 1: Build a provenance-backed component inventory

**Files:**
- Create: `packaging/appimage/licenses/components.json`
- Create: `packaging/appimage/licenses/runtime-type2.json`
- Test: `tests/test_appimage_licenses.py`
- Modify: `tests/test_packaging.py` only if the existing packaging conventions require shared fixtures.

**Interfaces:**
- Inventory records must include component name, version or explicit unknown state, architecture scope, SPDX expression/declared license, source package or upstream URL, artifact path, copyright/NOTICE evidence path, detection method and verification status.
- Runtime inventory records include runtime release, commit, architecture-specific SHA-256 and static components.

- [ ] Write tests rejecting missing required fields, duplicate component IDs, fabricated empty versions, unclassified license states and missing mimalloc.
- [ ] Run the focused tests and confirm expected RED failures.
- [ ] Add curated AppDir/runtime inventory data using only verified facts; mark unresolved versions as unknown with evidence gaps.
- [ ] Run focused tests and confirm GREEN.
- [ ] Run the full pytest suite.

### Task 2: Add project and third-party license payloads

**Files:**
- Create: `packaging/appimage/licenses/GPL-3.0-or-later.txt`
- Create: package-specific license/NOTICE/copyright files under `packaging/appimage/licenses/third-party/`
- Modify: `packaging/appimage/build-appimage.sh`
- Modify: `packaging/appimage/bundle-runtime.sh`
- Test: `tests/test_appimage_licenses.py`

- [ ] Write tests for complete GPL text, required third-party documents, exact CA certificate copyright source, libmpdec notice and separate GNOME resource provenance.
- [ ] Run focused tests and confirm expected RED failures.
- [ ] Add only upstream/Ubuntu package documents whose source and applicable component are verified.
- [ ] Add a deterministic staging step that copies required documents and an inventory manifest into the AppDir without overwriting distinct notices.
- [ ] Ensure the package-specific CA certificate copyright comes from Ubuntu `20260816ubuntu0.24.04.2`.
- [ ] Ensure libmpdec is associated with `_decimal` and Python 3.12.3-1ubuntu0.17 evidence.
- [ ] Run focused tests and full pytest suite.

### Task 3: Capture exact native package provenance

**Files:**
- Create or modify: `packaging/appimage/collect-licenses.sh`
- Modify: `packaging/appimage/build-appimage.sh`
- Modify: `packaging/appimage/bundle-runtime.sh`
- Test: `tests/test_appimage_licenses.py`

- [ ] Write tests for missing package copyright, package-version mismatch, compressed copyright files, and GNOME resources mapped to the wrong source package.
- [ ] Confirm RED.
- [ ] Implement package/file provenance collection using the native runner's package database and the actual bundled paths; do not equate the full apt install set with the bundled set.
- [ ] Capture exact package versions for each architecture and preserve package copyright/NOTICE files.
- [ ] Fail on a missing required document; report unknown optional provenance distinctly.
- [ ] Confirm GREEN and run full pytest suite.

### Task 4: Generate AppDir and aggregate SBOMs

**Files:**
- Create: `packaging/appimage/generate-sbom.py`
- Create: `packaging/appimage/install-syft.sh` (or an equivalent pinned installer)
- Modify: `packaging/appimage/build-appimage.sh`
- Modify: `packaging/appimage/licenses/runtime-type2.json`
- Test: `tests/test_appimage_licenses.py`

- [ ] Write tests for SPDX JSON and CycloneDX JSON generation, required runtime components, duplicate IDs, artifact metadata, architecture and AppDir/runtime reconciliation.
- [ ] Confirm RED.
- [ ] Pin Syft to a verified release and checksum; do not use an unpinned latest installer.
- [ ] Generate AppDir SPDX JSON 2.3 and CycloneDX JSON 1.6 using Syft.
- [ ] Implement a documented aggregate strategy that preserves Syft component data and adds Type 2 runtime components without invalid IDs or relationships.
- [ ] Validate aggregate SPDX/CycloneDX documents against their official schemas using pinned validation tooling.
- [ ] Bind all outputs to the final AppImage SHA-256 and architecture; avoid self-referential hash fields in the SBOM itself by using an external artifact manifest if needed.
- [ ] Confirm GREEN and run full pytest suite.

### Task 5: Verify extracted artifacts

**Files:**
- Modify: `packaging/appimage/test-appimage.sh`
- Test: `tests/test_appimage_licenses.py`
- Modify: `packaging/appimage/README.md`

- [ ] Write tests for missing license files, missing runtime inventory, malformed SPDX/CycloneDX, missing mimalloc, architecture mismatch, hash mismatch and undocumented component discrepancies.
- [ ] Confirm RED.
- [ ] Extend the native artifact test to validate the extracted AppDir, license tree, SBOMs, runtime inventory and artifact digest.
- [ ] Keep blocking errors distinct from justified warnings and unresolved non-blocking version gaps.
- [ ] Confirm GREEN and run all packaging tests.

### Task 6: Integrate native architecture CI

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/release-gate.yml` only if the existing release gate must consume the new evidence.
- Test: `tests/test_appimage_licenses.py`

- [ ] Write workflow-contract tests ensuring both native architectures generate and upload the complete evidence set.
- [ ] Confirm RED.
- [ ] Add pinned Syft/schema validation setup and run license/SBOM checks after AppDir assembly and after final AppImage creation.
- [ ] Ensure x86_64 and aarch64 produce separate artifacts and no cross-architecture substitution.
- [ ] Upload SPDX, CycloneDX, runtime inventory, license bundle and validation report as CI artifacts.
- [ ] Confirm GREEN locally where possible and through the PR CI matrix.

### Task 7: Documentation, changelog and final evidence

**Files:**
- Modify: `packaging/appimage/README.md`
- Modify: `CHANGELOG.md`
- Create: `docs/reports/APPIMAGE-LICENSE-SBOM-REMEDIATION.md`

- [ ] Write documentation tests for documented output paths, formats, runtime limitation and architecture-specific evidence.
- [ ] Confirm RED.
- [ ] Document regeneration, component provenance, license choices, unresolved evidence and SBOM semantics.
- [ ] Add a concise CHANGELOG entry.
- [ ] Run changelog validation, Ruff, mypy, full pytest, shell syntax checks and native AppImage CI.
- [ ] Review both architecture artifacts and SBOMs independently.
- [ ] Record every remaining unknown or exception; do not call the work complete if a material blocker remains.

## Verification commands

- `pytest -q`
- `ruff check .`
- `mypy clamguardian`
- `python scripts/validate_changelog.py CHANGELOG.md`
- `bash -n packaging/appimage/*.sh`
- `sh -n packaging/appimage/AppRun`
- Native CI: AppImage build and extracted-artifact verification on x86_64 and aarch64.
- SBOM validation: official SPDX 2.3 and CycloneDX 1.6 JSON schemas.

## Commit strategy

Use small, task-scoped commits after each task's RED→GREEN cycle. Preserve PR #38's existing history. Never force-push. Before updating the branch ref, compare its current head to the expected parent SHA; stop if it has moved unexpectedly.

## Completion contract

R1–R8 and LIC-001–LIC-020 have evidence; both architectures have independently passing artifact checks; SBOMs validate and include AppDir plus Type 2 runtime; documentation and CHANGELOG are updated; full CI is green; a final whole-branch review has no Critical or Important findings. PR #38 remains open and unmerged.
