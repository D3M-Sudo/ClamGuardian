# ClamGuardian-controlled AppImage Type 2 runtime — design

**Status:** Proposed; awaiting user approval  
**Date:** 2026-11-13  
**Target PR:** #39, branch `fix/appimage-license-sbom-followup`, base `feature`

## 1. Intent

Replace the precompiled upstream AppImage Type 2 runtime currently embedded by the AppImage packaging flow with a ClamGuardian-controlled runtime built from pinned source and build inputs. The objective is to close the engineering evidence gaps around statically linked libfuse and LGPL-2.1 §6 by making the exact runtime source, dependencies, build environment and relink procedure attributable to each published architecture.

The work is not a legal opinion and must not state that LGPL compliance is established merely because source files are present. Clearance remains blocked until the final x86_64 and aarch64 artifacts are independently checked and a practical modified-libfuse relink has been demonstrated.

## 2. Current implementation and constraints

The current AppImage pipeline in `packaging/appimage/build-appimage.sh` invokes `bundle-runtime.sh` to assemble the AppDir, then invokes the pinned appimagetool without supplying a ClamGuardian-built runtime. The resulting AppImage therefore receives the Type 2 runtime from the appimagetool/upstream packaging path.

PR #39 currently records upstream Type 2 runtime release `20251108`, commit `dd6cebedcbddde9c82f89b011e8e1d40b6e43868`. Its preserved upstream Dockerfile uses Alpine 3.21 and unversioned `apk add`; the Makefile statically links squashfuse, zstd, zlib, libfuse3 and mimalloc. The source bundle includes sources and a recipe, but it does not prove the exact historical mimalloc provider/revision or demonstrate a completed relink. Its own manifest correctly says LGPL clearance is not established.

The existing CI already builds AppImages natively on x86_64 and aarch64 runners and tests the extracted artifacts. This architecture split must remain; one architecture's runtime must never be relabelled for the other.

Relevant current files include:
- `packaging/appimage/build-appimage.sh`
- `packaging/appimage/collect-runtime-source-bundle.sh`
- `packaging/appimage/licenses/runtime-type2.json`
- `packaging/appimage/test-appimage.sh`
- `.github/workflows/ci.yml`
- `packaging/appimage/assemble-release-evidence.sh`

## 3. Goals

1. Build the Type 2 runtime from source under ClamGuardian-controlled, versioned build inputs for x86_64 and aarch64.
2. Pin and record the runtime source, libfuse source and patch, squashfuse source, static dependency versions, toolchain/container identity, package revisions and source checksums.
3. Embed the newly built runtime into each architecture's AppImage instead of accepting the upstream precompiled runtime implicitly.
4. Ship complete machine-readable source and build materials sufficient to rebuild the runtime and relink it against a modified libfuse.
5. Add automated checks that bind the runtime embedded in each AppImage to the runtime produced by that architecture's build.
6. Demonstrate a practical relink test on both architectures, including a controlled libfuse source modification whose effect is observable in the resulting runtime.
7. Preserve license texts, per-component provenance, SBOM declarations and conservative unknown/NOASSERTION semantics.
8. Keep PR #39 Draft until all evidence gates and current-head CI pass.

## 4. Non-goals and anti-goals

- Do not change the application's Python/GTK runtime architecture or unrelated packaging behavior.
- Do not switch libfuse to dynamic linking as a shortcut; static linking is retained and its obligations are addressed through source/relink materials.
- Do not infer historical dependency versions from candidate source archives. The new build must establish its own exact provenance.
- Do not claim legal compliance, legal approval or release readiness from CI success alone.
- Do not modify protected branch `feature`, merge the PR, create tags or publish releases during implementation.
- Do not silently replace the runtime for only one architecture.

## 5. Approaches considered

### A. Recover the historical upstream build provenance

Recover the exact upstream Alpine package database, dependency revisions and original build environment for the precompiled runtime, then prove relinkability from those materials.

**Trade-off:** least change to the shipped runtime, but the upstream build did not retain the exact installed APK database and the missing historical evidence may be unrecoverable. A source candidate is not proof of the linked binary.

### B. Build and own the Type 2 runtime in ClamGuardian — selected

Build the runtime from pinned source and controlled build inputs for each architecture, then explicitly pass that runtime into AppImage assembly. Produce source, package/toolchain provenance, checksums and a reproducible relink procedure as first-class CI evidence.

**Trade-off:** larger implementation and maintenance burden, and it changes the runtime binary. It removes dependence on unknown historical upstream package selections and gives ClamGuardian direct control over future provenance.

### C. Dynamically link libfuse

Change the Type 2 runtime so libfuse is loaded dynamically and rely on a separately supplied compatible library.

**Trade-off:** weakens the current self-contained AppImage runtime and introduces host/runtime library compatibility and availability dependencies. It does not fit the existing portability design.

Approach B is selected because it provides the strongest controllable evidence while preserving static linking and native per-architecture packaging.

## 6. Proposed design

### 6.1 Controlled build environment

Create a dedicated runtime build definition under `packaging/appimage/runtime/`. It must identify an immutable base image/toolchain and an immutable package source or repository snapshot. Every installed build dependency must be recorded with its exact package version/revision and checksum where the package format supports it. Floating tags, unpinned `apk add` inputs and mutable source refs are prohibited.

The implementation may use a pinned Alpine 3.21 image and a fixed repository snapshot, or an equivalently immutable build environment. The final design choice must be justified by what can be made available and repeatable for both architectures. Record `apk info -vv` (or equivalent package inventory), compiler/linker versions, architecture, build flags, source revision and `SOURCE_DATE_EPOCH` in build metadata.

### 6.2 Runtime source and dependency graph

Build the Type 2 runtime from its pinned source revision and preserve the exact runtime source used. Build and statically link:
- libfuse 3.15.0, including the upstream `mount.c.diff` patch required by Type 2 runtime;
- squashfuse 0.5.2;
- zstd, zlib, musl and mimalloc at exact versions established by the controlled build.

The final inventory must describe the actual new build, not the old upstream binary. Each component entry must distinguish upstream version, source package, binary package where applicable, package revision, source digest, license identifier/text evidence, architecture and verification status. Unknown values remain explicit; no version may be inferred solely from a similarly named package or candidate archive.

### 6.3 AppImage integration

Modify the AppImage build path to build or consume the runtime produced for the current native architecture and explicitly supply it to the pinned appimagetool using its supported runtime-injection interface. Fail closed if the runtime is missing, has the wrong architecture, is not the expected static executable, or does not match its build manifest.

The extracted-artifact test must extract the Type 2 runtime from the finished AppImage and compare its digest and architecture with the runtime build output. The existing AppImage CLI, GTK, license and SBOM checks remain in place.

### 6.4 Source and relink materials

For each architecture, publish an evidence bundle containing:
- complete source for the Type 2 runtime and all statically linked libraries, including the exact libfuse patch;
- exact build definitions, toolchain/container identity, package repository snapshot references and package inventory;
- checksums for every source archive, patch, build input and produced runtime;
- build commands and environment variables needed to rebuild;
- license and copyright materials for the included components;
- a machine-readable manifest binding architecture, source inputs, build metadata and runtime output digest.

The bundle must be self-contained except for explicitly documented immutable external inputs. It must not use the existing `mimalloc-2.1.7-candidate` wording or preserve unknown versions where the controlled build can establish exact values.

### 6.5 Relinkability test

Add an automated, architecture-native test that starts from the shipped source/build bundle, builds libfuse, and links a replacement Type 2 runtime. The test must then modify the libfuse source in a controlled, non-functional way, rebuild libfuse, relink the runtime, and prove that the resulting executable contains or otherwise exposes the expected test marker while remaining a valid runtime binary.

The test must prove the modified library was actually incorporated into the replacement runtime; a successful build of libfuse alone or a repeat build using unchanged inputs is insufficient. It must run independently for x86_64 and aarch64. The exact marker mechanism is an implementation detail, but it must be robust against linker dead-code elimination and verified from the produced executable or a runtime-level assertion.

### 6.6 CI and release evidence

Extend the existing native AppImage jobs rather than introducing cross-architecture substitution. CI must:
- build the controlled runtime on each native runner;
- run the modified-libfuse relink test;
- inject the runtime into the AppImage;
- verify embedded runtime digest/architecture;
- run the existing AppImage extracted-artifact checks;
- upload the runtime binary, source/relink bundle, build manifest, checksums and test logs for each architecture.

The release evidence assembler must include the new runtime provenance and relink evidence for both architectures. The release workflow's existing draft/publishing controls must remain unchanged.

### 6.7 Documentation and SBOM

Update `runtime-type2.json`, the AppImage README, CHANGELOG and remediation report to describe the new ClamGuardian-controlled runtime and its actual component versions. Preserve the distinction between SPDX declared and concluded license values. Do not downgrade a component's evidence status or replace unresolved package-level declarations with guesses.

The report must state exactly which relink tests ran, on which architectures, against which runtime and libfuse source digests, and which checks remain outstanding. CI passing is engineering evidence, not a legal conclusion.

## 7. Verification and acceptance gates

All gates are mandatory before PR #39 can leave Draft:

1. **Input provenance:** immutable source refs/digests, immutable build environment, exact package/toolchain inventory for both architectures.
2. **Runtime build:** native x86_64 and aarch64 builds succeed from the declared inputs.
3. **Runtime identity:** each final AppImage contains the exact runtime binary produced by its matching architecture build.
4. **Relink proof:** modified-libfuse rebuild and replacement-runtime relink succeed and the test marker is verified on both architectures.
5. **Source completeness:** bundle contains the corresponding source and machine-readable build/relink instructions, with checksums verified.
6. **License/SBOM:** all static runtime components and their notices are represented accurately; no unsupported package-wide SPDX conclusions.
7. **Regression:** full CI and Release Gate pass on the exact final PR head; fresh artifacts are downloaded and inspected, not inferred from an earlier run.
8. **Independent review:** the final source/relink bundles and evidence are reviewed separately. Any unresolved LGPL §6 question remains a blocker.

If any gate cannot be met, PR #39 remains Draft and the remediation report records the exact blocker. No merge, tag or release is performed as part of this implementation phase.

## 8. Builder decisions

The implementation owner may choose the exact pinned image digest/repository snapshot mechanism, runtime injection interface supported by the pinned appimagetool, and robust relink marker technique. Those choices must satisfy the acceptance gates above and be documented. Changes to architecture, static-linking strategy, supported platforms or the compliance gate require renewed user approval.

## 9. Approval boundary

This document proposes the design only. No production code, runtime build configuration, dependency changes or CI behavior may be changed until the user approves this design. After approval, create the implementation plan and execute it test-first on the PR branch, leaving `feature` untouched.
