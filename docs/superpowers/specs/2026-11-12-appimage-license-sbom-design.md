# ClamGuardian AppImage License & SBOM Remediation — Design

**Date:** 2026-11-12  
**Repository:** D3M-Sudo/ClamGuardian  
**Delivery:** PR #38, branch `ci/node24-actions`, target `feature`  
**Baseline:** `c64b6541512bb0cb9d2b5e452e01d6da1b578c2d`  
**Status:** Approved by repository owner; implementation plan and execution follow separately.

## Intent

Make the licensing, copyright, provenance and SBOM evidence for ClamGuardian AppImages complete and reproducible for x86_64 and aarch64. Verification must cover the extracted AppDir and the AppImage Type 2 runtime, which is outside the SquashFS filesystem.

This is an engineering evidence and packaging task, not a legal opinion or a declaration of legal compliance.

## Goals

- Ship the complete project GPL-3.0-or-later license text.
- Preserve required third-party license, copyright and NOTICE material for bundled components.
- Identify components, versions, licenses, provenance and evidence.
- Produce AppDir SPDX JSON and CycloneDX JSON SBOMs, a separate Type 2 runtime inventory, and aggregate SBOMs that represent the whole AppImage.
- Verify the extracted AppImage independently on native x86_64 and aarch64 runners.
- Fail CI for missing required evidence, invalid SBOMs, or unresolved blocking inventory discrepancies.
- Keep the existing AppImage build model, pinned tools and native architecture builds.

## Non-goals

- No application feature or runtime behavior changes.
- No Flatpak license remediation unless a shared test/documentation change is required.
- No release, tag, merge, or publication.
- No unsupported legal conclusions based solely on automated scanner output.

## Constraints

- All changes stay on `ci/node24-actions` within PR #38.
- Never modify `feature` directly.
- No merge, tag, or release.
- Do not invent package versions, license expressions, copyright holders, or source provenance.
- Unknown facts remain explicitly unknown and block a compliance claim where material.
- Keep architecture-specific evidence separate.
- Update CHANGELOG and packaging documentation.
- Use test-first implementation; run the complete relevant CI matrix before reporting completion.

## Required remediation

### R1 — Project license
Replace the abbreviated license declaration with the complete GPL-3.0-or-later text, preserve project attribution, copy it into the AppDir, and assert its presence/content in the extracted artifact.

### R2 — AppImage Type 2 runtime
Maintain a distinct runtime inventory tied to release `20251108`, upstream commit `dd6cebedcbddde9c82f89b011e8e1d40b6e43868`, architecture and verified SHA-256:
- x86_64: `2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d`
- aarch64: `00cbdfcf917cc6c0ff6d3347d59e0ca1f7f45a6df1a428a0d6d8a78664d87444`

Inventory musl, libfuse 3.15.0, squashfuse 0.5.2, zstd, zlib and mimalloc. The Makefile links mimalloc although the reviewed license list did not mention it. Verify versions and notices from upstream evidence; do not infer exact Alpine package versions from the runtime commit. Document LGPL-2.1 linking/source obligations where applicable.

### R3 — Native and Python components
Preserve package/wheel license and copyright metadata. Specifically cover LZO 2.10 (GPL-2.0-or-later), PyGObject 3.48.2-1 (LGPL-2.1-or-later), Pycairo 1.25.1-2build2 (MPL-1.1/LGPL-2.1-only; determine applicability), dconf `libdconfsettings.so` (LGPL-2.1-or-later), and the 13 runtime wheels listed in the approved remediation specification. Identify native extensions and required NOTICE/copyright files.

### R4 — GNOME/GTK resources
Inventory Adwaita icon theme 46.0-1, hicolor icon theme 0.17-2, GSettings schemas 46.1-0ubuntu1 and the copied GTK4, Libadwaita, Adwaita theme, icon and schema resources separately by their actual source packages. Adwaita's upstream licensing offers LGPL-3.0 or CC-BY-SA-3.0 US; record the applicable choice and attribution, not both as cumulative obligations.

### R5 — CA certificates and libmpdec
For `ca-certificates 20260816ubuntu0.24.04.2`, preserve the exact Ubuntu package copyright and record the provenance of `ca-certificates.crt`. Do not substitute generic Debian copyright.
Treat libmpdec as embedded in Python 3.12.3-1ubuntu0.17's `_decimal` build; include its version/evidence, copyright and redistribution notice, plus relevant Python package copyright.

### R6 — SBOM architecture
Generate AppDir SPDX JSON and CycloneDX JSON with Syft. Maintain a separately curated Type 2 runtime inventory. Generate aggregate SPDX and CycloneDX documents representing both AppDir and runtime components. The AppDir scan alone is not a complete AppImage SBOM. Pin Syft and validate output schemas; bind every document to architecture and final artifact SHA-256.

### R7 — Artifact tests
Extend packaging tests to extract the actual AppImage and verify project license, third-party notices, component inventory, SBOM schemas, aggregate/runtime reconciliation and artifact hashes. Distinguish blocking errors, unknown versions, justified warnings and documented exclusions. No blanket suppression.

### R8 — Independent aarch64 verification
Extract and validate the native aarch64 AppImage independently. Produce its own inventory and SBOMs and compare with x86_64 without assuming parity.

## Acceptance

All R1–R8 requirements and LIC-001–LIC-020 controls from the approved specification must be implemented and evidenced. Both native architecture builds must pass. All required license and copyright material must be present in the extracted artifacts. SBOMs must validate and represent AppDir plus runtime. CHANGELOG and documentation must be updated. Any unresolved material evidence gap must be reported explicitly; it cannot be labelled compliant.

## Approaches considered

1. **AppDir-only Syft scan:** rejected because it omits Type 2 runtime components outside SquashFS.
2. **Manually curated SBOM only:** rejected because it does not provide automated discovery/reconciliation of AppDir contents.
3. **SBOM-first plus curated runtime inventory and reconciliation:** selected. It combines automated AppDir discovery with explicit evidence for static/runtime components Syft cannot observe in the AppDir scan.

## Remaining implementation decisions

The implementer must verify Syft pinning and schema validation tooling, exact package-to-file provenance, the supported aggregate-document merge strategy, and the actual package metadata available on both native runners. Any material deviation must be recorded and reported.
