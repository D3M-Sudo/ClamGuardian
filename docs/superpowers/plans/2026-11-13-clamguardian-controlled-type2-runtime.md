# ClamGuardian-controlled Type 2 Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the upstream precompiled AppImage Type 2 runtime with a ClamGuardian-built, provenance-pinned static runtime and demonstrate modified-libfuse relinkability on x86_64 and aarch64.

**Architecture:** Add a native, per-architecture runtime build pipeline under `packaging/appimage/runtime/`, using immutable source inputs and a pinned build environment. Inject the produced executable through the existing appimagetool `--runtime-file` interface, and bind the embedded runtime to its build manifest by SHA-256. Export complete source/build/relink evidence and execute a modified-libfuse relink test on each native CI runner.

**Tech Stack:** Bash, Python 3.12, Docker/BuildKit or an equivalently immutable container build, Alpine APK tooling (if selected), appimagetool 1.9.1, pytest, GitHub Actions, Syft SPDX 2.3/CycloneDX 1.6.

**Spec:** `docs/superpowers/specs/2026-11-13-clamguardian-controlled-type2-runtime-design.md`

## Global Constraints

- Target branch is `fix/appimage-license-sbom-followup`; never modify protected `feature`.
- Keep PR #39 Draft until every acceptance gate in the spec passes.
- Keep static libfuse linking; do not switch to dynamic linking.
- Build independently and natively for x86_64 and aarch64; never relabel or reuse a foreign-architecture runtime.
- Pin all source refs, source hashes, build environment identity, package versions/revisions and toolchain versions.
- Never infer a linked component version from a candidate archive or package name.
- Preserve SPDX `NOASSERTION`/unknown semantics; do not claim legal compliance from source presence or CI success.
- No merge, tag, release publication or protected-branch write during this plan.
- Use TDD for behavior and validation code: write each test first, observe the expected failure, implement the minimum, then rerun it.
- Update CHANGELOG and technical evidence documentation with the implementation.

## Review Focus

1. **Wrong-architecture or substituted runtime:** reject an ELF runtime that does not match the native runner and declared architecture; test both architecture identifiers and mismatch cases.
2. **Mutable or incomplete build inputs:** fail if source digest, image identity, package revision or toolchain provenance is missing; test missing and altered manifest fields.
3. **Runtime not actually embedded:** extract the final AppImage and compare the embedded runtime digest with the build output; test mismatch and missing runtime.
4. **False-positive relink test:** prove a modified libfuse object is linked into the replacement runtime, not merely compiled; test absence and presence of the marker.
5. **Evidence bundle drift:** reject missing sources, patches, licenses, build definitions or checksum mismatches; test incomplete and tampered bundles.

---

### Task 1: Runtime build contract and provenance manifest

**Files:**
- Create: `packaging/appimage/runtime/README.md`
- Create: `packaging/appimage/runtime/runtime-build.json` (schema/contract example or schema, as appropriate to existing repository conventions)
- Create: `packaging/appimage/runtime/validate-runtime-manifest.py`
- Create: `tests/test_appimage_runtime_manifest.py`
- Modify: `packaging/appimage/licenses/runtime-type2.json` only when the new controlled inventory is available in a later task.

**Interfaces:**
- Validator CLI: `validate-runtime-manifest.py MANIFEST --architecture ARCH --runtime RUNTIME`; exit non-zero on invalid or incomplete evidence.
- Manifest must include architecture, runtime source commit, source archive SHA-256, build-environment immutable identity, package inventory, compiler/linker versions, build flags, `SOURCE_DATE_EPOCH`, component source hashes/licenses, output runtime SHA-256 and ELF properties.

- [ ] **Step 1: Write failing manifest tests** for missing architecture, unsupported architecture, absent immutable image identity, missing package revision, invalid SHA-256, runtime digest mismatch, and architecture mismatch.
- [ ] **Step 2: Run** `pytest tests/test_appimage_runtime_manifest.py -q`. Expected: failures because the validator/contract is not implemented.
- [ ] **Step 3: Implement** the strict JSON manifest validator. Reject unknown architecture, absent required provenance, mutable image references, empty package inventory, invalid digests, and a runtime whose digest/ELF architecture differs from the manifest.
- [ ] **Step 4: Add positive fixtures** for x86_64 and aarch64 and ensure the validator accepts only matching runtime metadata.
- [ ] **Step 5: Run** `pytest tests/test_appimage_runtime_manifest.py -q`. Expected: all manifest tests pass.
- [ ] **Step 6: Commit** as `test(appimage): define controlled runtime provenance contract`.

### Task 2: Immutable native runtime build environment and source acquisition

**Files:**
- Create: `packaging/appimage/runtime/Dockerfile` (or a documented equivalent if BuildKit/OCI execution is not viable)
- Create: `packaging/appimage/runtime/build-runtime.sh`
- Create: `packaging/appimage/runtime/fetch-sources.sh`
- Create: `packaging/appimage/runtime/sources.lock`
- Create: `packaging/appimage/runtime/patches/` for the exact libfuse patch and any ClamGuardian-owned changes
- Create: `tests/test_appimage_runtime_build_inputs.py`
- Modify: `.github/workflows/ci.yml` only in Task 5.

**Interfaces:**
- Build entry point: `build-runtime.sh --architecture x86_64|aarch64 --output-dir DIR`.
- Source lock records immutable source URL/ref, version, SHA-256 and license evidence for Type2 runtime, libfuse 3.15.0, squashfuse 0.5.2, zstd, zlib, musl and mimalloc.
- Build must emit `runtime`, `runtime-build.json`, package inventory and a build log into the requested output directory.

- [ ] **Step 1: Write failing input-lock tests** for floating refs/tags, absent hashes, duplicate components, missing licenses and architecture-incompatible source/build settings.
- [ ] **Step 2: Run** `pytest tests/test_appimage_runtime_build_inputs.py -q`. Expected: failures because the source-lock validator does not exist.
- [ ] **Step 3: Implement** immutable source acquisition with SHA-256 verification and fail-closed lock validation.
- [ ] **Step 4: Select and pin** an immutable multi-architecture build image digest and an immutable package repository snapshot (or build dependencies from pinned source archives). Pin every installed package revision; capture the complete installed package inventory and compiler/linker versions. Do not use unversioned `apk add` or floating container tags.
- [ ] **Step 5: Implement** native compilation of Type2 runtime plus static libfuse, squashfuse, zstd, zlib, musl and mimalloc. Preserve the required libfuse patch and ensure the link command explicitly links the intended static libraries.
- [ ] **Step 6: Emit** the runtime binary, source/build metadata, exact package inventory, compiler/linker versions, build flags, `SOURCE_DATE_EPOCH`, source digests and output digest. Feed the manifest through Task 1's validator.
- [ ] **Step 7: Add tests** for tampered source archives, missing package metadata and non-native architecture attempts.
- [ ] **Step 8: Run** `pytest tests/test_appimage_runtime_build_inputs.py tests/test_appimage_runtime_manifest.py -q`, plus native x86_64 build and aarch64 build on matching runners. Expected: tests and both native builds pass.
- [ ] **Step 9: Commit** as `build(appimage): compile pinned Type 2 runtime from source`.

### Task 3: Modified-libfuse relink proof

**Files:**
- Create: `packaging/appimage/runtime/test-relink.sh`
- Create: `packaging/appimage/runtime/relink-marker.patch` or equivalent controlled test-only source mutation.
- Create: `tests/test_appimage_runtime_relink.py`
- Modify: `packaging/appimage/runtime/README.md`

**Interfaces:**
- Test entry point: `test-relink.sh --architecture ARCH --source-bundle DIR --output-dir DIR`.
- The test must produce a replacement runtime, a relink manifest and logs proving the modified libfuse source digest and marker are present in the final executable.

- [ ] **Step 1: Write failing tests** requiring the test to fail when the source mutation is absent, the marker is not linked, the replacement runtime is missing, or the replacement runtime architecture is wrong.
- [ ] **Step 2: Run** `pytest tests/test_appimage_runtime_relink.py -q`. Expected: failure because the relink test interface is not implemented.
- [ ] **Step 3: Implement** a controlled, non-functional libfuse source mutation that creates a unique marker in a code path guaranteed to be linked into the Type2 runtime. Ensure linker garbage collection cannot discard the marker.
- [ ] **Step 4: Implement** the relink test: build original libfuse/runtime from the shipped materials, apply the controlled source mutation, rebuild libfuse, relink Type2 runtime, and verify the marker from the resulting executable plus ELF architecture and static-link properties.
- [ ] **Step 5: Ensure** the test starts from the source/relink materials that will be shipped, not from an unrelated developer checkout or hidden runner state.
- [ ] **Step 6: Run** `pytest tests/test_appimage_runtime_relink.py -q` and run the relink test natively on x86_64 and aarch64. Expected: both architectures prove the modified libfuse marker is present in the replacement runtime.
- [ ] **Step 7: Commit** as `test(appimage): prove static libfuse runtime relinkability`.

### Task 4: AppImage runtime injection and embedded identity verification

**Files:**
- Modify: `packaging/appimage/install-appimagetool.sh`
- Modify: `packaging/appimage/build-appimage.sh`
- Modify: `packaging/appimage/test-appimage.sh`
- Create: `packaging/appimage/runtime/verify-embedded-runtime.py`
- Create: `tests/test_appimage_runtime_injection.py`

**Interfaces:**
- `install-appimagetool.sh` must continue exporting the pinned appimagetool binary/wrapper but must no longer download or select the upstream precompiled runtime.
- `build-appimage.sh` must pass the output of Task 2 as `--runtime-file` to the existing wrapper.
- Embedded-runtime verifier CLI: `verify-embedded-runtime.py APPIMAGE --architecture ARCH --expected-runtime FILE --manifest FILE`.

- [ ] **Step 1: Write failing tests** for missing runtime, mismatched architecture, wrong runtime hash, wrapper argument forwarding and extracted runtime digest mismatch.
- [ ] **Step 2: Run** `pytest tests/test_appimage_runtime_injection.py -q`. Expected: failures against the current upstream-runtime selection path.
- [ ] **Step 3: Implement** strict wrapper handling that preserves caller-supplied `--runtime-file` and rejects missing/duplicate values; remove the upstream runtime download and hash constants.
- [ ] **Step 4: Integrate** native runtime build output into `build-appimage.sh`; validate the manifest before appimagetool runs and explicitly pass the matching runtime.
- [ ] **Step 5: Implement** extracted AppImage runtime verification. Compare its SHA-256 and ELF architecture against the build manifest/output; fail if extraction or identity checks fail.
- [ ] **Step 6: Update** `test-appimage.sh` to invoke the verifier while preserving existing CLI, GTK, license and SBOM checks.
- [ ] **Step 7: Run** `pytest tests/test_appimage_runtime_injection.py tests/test_appimage_runtime_manifest.py -q`, then build and test a native AppImage. Expected: embedded runtime digest equals the matching build output.
- [ ] **Step 8: Commit** as `build(appimage): inject ClamGuardian-controlled Type 2 runtime`.

### Task 5: Native CI and release evidence integration

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/release.yml`
- Modify: `packaging/appimage/assemble-release-evidence.sh`
- Modify: `tests/test_appimage_release_evidence.py` (or the existing corresponding evidence test discovered during implementation)
- Create: `tests/test_appimage_runtime_ci_contract.py`

**Interfaces:**
- Each native AppImage matrix job must upload its runtime executable, source/relink bundle, runtime manifest, checksums, package inventory and relink logs alongside existing SBOM/license evidence.
- Release evidence assembler must require exactly one complete runtime evidence set for each architecture and include it in that architecture's SBOM/evidence archive.

- [ ] **Step 1: Write failing workflow/evidence tests** requiring both architectures, build/relink steps, uploaded evidence names, release artifact cardinality, and rejection of missing or duplicate evidence.
- [ ] **Step 2: Run** the focused pytest file. Expected: failure because the new runtime build/relink CI contract is absent.
- [ ] **Step 3: Extend** native AppImage CI jobs to build and validate runtime, run modified-libfuse relink proof, inject runtime, test the AppImage, and upload all evidence for the same architecture.
- [ ] **Step 4: Extend** the tagged release AppImage jobs and release evidence assembler to preserve the same runtime provenance and relink proof. Keep the existing Draft creation/manual publication controls unchanged.
- [ ] **Step 5: Add** strict release evidence checks for both architectures: no missing, duplicate, mismatched or checksum-invalid runtime files.
- [ ] **Step 6: Run** `pytest tests/test_appimage_runtime_ci_contract.py` and all relevant packaging/evidence tests. Expected: all tests pass and both architecture workflows have equivalent evidence contracts.
- [ ] **Step 7: Commit** as `ci(appimage): verify and publish runtime relink evidence`.

### Task 6: SBOM, license inventory and source bundle refresh

**Files:**
- Modify: `packaging/appimage/licenses/runtime-type2.json`
- Modify: `packaging/appimage/collect-runtime-source-bundle.sh` or replace it with a collector for the ClamGuardian-controlled build outputs.
- Modify: `packaging/appimage/generate-sbom.py`
- Modify: `packaging/appimage/verify-sbom.py`
- Modify: `packaging/appimage/test-appimage.sh`
- Modify: `tests/test_appimage_license_runtime_evidence.py`
- Modify: `tests/test_appimage_sbom.py` (or the existing runtime SBOM test module)

**Interfaces:**
- Runtime inventory schema must describe the new controlled runtime and exact built components; architecture-specific build provenance remains in each runtime manifest.
- Source bundle must contain all runtime/library sources, patches, build definitions, toolchain and package metadata, licenses, build/relink instructions and verified checksums.

- [ ] **Step 1: Write failing tests** for exact component version/source/license mapping, missing source/patch/license files, invalid checksums, incorrect architecture and mismatch between SBOM runtime inventory and build manifest.
- [ ] **Step 2: Run** the focused SBOM/license tests. Expected: failures for the new runtime inventory/bundle contract.
- [ ] **Step 3: Update** runtime inventory from actual controlled build outputs only. Remove the historical mimalloc candidate wording and record actual version/package revision/source digest from the new build.
- [ ] **Step 4: Implement** source bundle collection from the exact build inputs/outputs, including complete sources and the test relink materials. Verify every bundle entry against SHA256SUMS.
- [ ] **Step 5: Update** SBOM generation and verification so the runtime and all statically linked components are represented accurately without package-wide license overclaims.
- [ ] **Step 6: Run** focused license/SBOM tests and generate/validate both architecture SBOMs. Expected: schema and semantic checks pass, with no unsubstantiated `verified` claims.
- [ ] **Step 7: Commit** as `docs(appimage): bind runtime SBOM to controlled build provenance`.

### Task 7: Documentation and changelog

**Files:**
- Modify: `packaging/appimage/README.md`
- Modify: `packaging/appimage/runtime/README.md`
- Modify: `docs/reports/APPIMAGE-LICENSE-SBOM-REMEDIATION.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Document** the controlled build prerequisites, native build commands, pinned inputs, architecture outputs, relink procedure, evidence bundle contents and maintenance/update procedure.
- [ ] **Step 2: Update** the remediation report with exact build/relink evidence, source digests, artifact digests, architecture results and any residual limitations. Do not state legal clearance unless the evidence and independent review support it.
- [ ] **Step 3: Update** the Unreleased changelog with the controlled runtime, reproducible source/relink evidence and dual-architecture validation.
- [ ] **Step 4: Run** `python scripts/validate_changelog.py CHANGELOG.md` and documentation/link/path checks available in the repository.
- [ ] **Step 5: Commit** as `docs(appimage): document controlled runtime and relink process`.

### Task 8: Full verification, artifact inspection and independent review

**Files:**
- No planned source changes unless a review finding requires a TDD fix.
- Evidence: fresh CI AppImage artifacts and per-architecture runtime/source/relink bundles.

- [ ] **Step 1: Run** the complete Python test suite, lint, type checks, shell syntax checks and all packaging/license/SBOM tests.
- [ ] **Step 2: Run** full CI and Release Gate on the exact final PR head; confirm every required job is green and distinguish skipped jobs from passed jobs.
- [ ] **Step 3: Download fresh x86_64 and aarch64 artifacts from that exact run; verify outer checksums, AppImage checksums, embedded runtime checksums, source-bundle checksums, manifests, licenses, SBOMs and relink logs.
- [ ] **Step 4: Review** both architecture bundles independently against LGPL-2.1 §6(a)'s source/relink evidence expectations. Record unresolved legal or provenance questions as blockers; do not substitute a CI pass for this review.
- [ ] **Step 5: Perform** a fresh whole-branch code review using the requesting-code-review checklist. Fix Critical/Important findings with RED→GREEN tests and a full suite run; record Minor findings without silently expanding scope.
- [ ] **Step 6: Run** the AI Delivery Evidence Checker against the final implementation claims and collected artifacts. Treat its result as evidence review, not legal certification.
- [ ] **Step 7: Confirm** all spec acceptance gates are satisfied. If any gate remains unresolved, leave PR #39 Draft and report the exact blocker. Only after all gates pass may the PR be considered for Ready/merge; this plan does not itself authorize a merge or release action.
- [ ] **Step 8: Commit** any final evidence/report updates on the PR branch and rerun all affected verification on the resulting exact HEAD.

---

## Execution notes

- Work in an isolated Git worktree created using the Superpowers worktree workflow. Do not edit the user's default checkout or protected branches.
- Maintain a plan progress ledger under the plan-specific ignored `.superpowers/sdd/` workspace.
- Each task is independently committed and its named tests are run before and after implementation.
- If the pinned upstream Type2 source or package snapshot cannot be made available immutably for both architectures, stop and record the blocker rather than weakening the pinning requirement.
- If the modified-libfuse marker cannot be shown to be present in the final statically linked runtime, the relink gate has not passed.
