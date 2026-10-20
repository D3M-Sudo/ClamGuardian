# Release 1.0.1 — plan and checklist

Status: **release candidate prepared, tag NOT cut**. The remaining blocker is the
manual desktop validation of Phase D4, which requires the maintainer's local host.

Baseline for this release: `feature` @ `4a3d165` plus the release-engineering
changes listed in §2. `feature` is 24 commits ahead of `main` (`ca887aa`, tag
`v1.0.0` → `8ee8a56`).

## 1. Why 1.0.1 exists

`v1.0.0` ships the P1 defect **AUD-01**: when a directory scan is served by
`clamd`, the response was not read to EOF, so a directory containing a clean file
followed by an infected one could be reported as `clean`. The fix (read to EOF
with an 8 MiB cap, plus the newline-injection fix AUD-04) is on `feature` since
PR #13 but has never been released. Audit recommendation R1 explicitly asks for a
`1.0.1` security release.

1.0.1 also carries the complete GTK4 desktop application, which the roadmap
places in the `1.0.x` line.

## 2. Contents of the release-engineering change

| File | Change |
|---|---|
| `pyproject.toml`, `clamguardian/__init__.py` | version `1.0.0` → `1.0.1` |
| `data/io.github.clamguardian.ClamGuardian.metainfo.xml` | new `<release version="1.0.1">` entry (the packaging test asserts `__version__` is listed) |
| `packaging/flatpak/io.github.clamguardian.ClamGuardian.yml` | release source pinned to `tag: v1.0.1` |
| `.github/workflows/release-gate.yml` | D4 smoke patch applied (every page, settings, stylesheet, About); release artifact renamed to `ClamGuardian-v1.0.1-linux-x86_64.flatpak`; gate label updated |
| `tests/test_packaging.py` | guard: the release manifest must pin `v<current version>` |
| `CHANGELOG.md` | new, 1.0.1 + 1.0.0 |
| `SECURITY.md` | new: supported versions, private reporting, scope |
| `docs/project/D4-RELEASE-GATE.md` | records that the D4 workflow patch is applied |
| `README.md`, `docs/ROADMAP.md` | security note for `v1.0.0`, protection model corrected, release state |

## 3. Checklist

### Done in this branch

- [x] Version bumped in `pyproject.toml` and `clamguardian/__init__.py`.
- [x] AppStream release entry added.
- [x] Release Flatpak manifest pinned to `v1.0.1`.
- [x] D4 release-gate patch applied (`git apply --check` was clean on `4a3d165`).
- [x] `CHANGELOG.md`, `SECURITY.md`, this document.
- [x] Packaging guard test added.
- [x] No tag, no promotion, no merge: `main`, `testing`, `development` untouched.

### Blocked — maintainer only

- [ ] **Desktop validation** (`DESKTOP-TEST-D4-2026-10-19.md`, 14 steps) on the
      real host with ClamAV installed.
- [ ] **Flatpak quarantine restore** (`DESKTOP-TEST-1.0.md` §8): record whether
      `--filesystem=host:ro` blocks writes; document supported destinations
      instead of widening permissions.
- [ ] Record the commit under test and the outcomes in both validation files.

### After the validation is recorded

- [ ] `ruff check .` — green.
- [ ] `mypy clamguardian` — green.
- [ ] `pytest` — green (local, optional GTK extra).
- [ ] `uv lock --check` and `pip-audit --strict` — clean.
- [ ] Apply/commit the workflow change with a token that has `workflows`
      permission (the automation app cannot push `.github/workflows/*`).
- [ ] PR `feature → testing`; require CI (3.11/3.12/3.13 + 3.14) and the release
      gate including `ClamGuardian-testing-linux-x86_64.flatpak`.
- [ ] PR `testing → development`; PR `development → main`.
- [ ] Annotated tag `v1.0.1` on `main` (`git tag -a v1.0.1 -m "ClamGuardian 1.0.1"`).
- [ ] Release Gate on the tag: `flatpak-release` builds `ClamGuardian-v1.0.1-linux-x86_64.flatpak`.
- [ ] Publish the GitHub Release with the bundle plus its SHA-256.
- [ ] Post-release docs: `README.md` install snippet → `v1.0.1`,
      `docs/ROADMAP.md` release table, `docs/reports/RELEASE-GATE-1.0.md` pointer.
- [ ] Delete the release-engineering branch after the merge.

## 4. Acceptance criteria

| Criterion | Evidence |
|---|---|
| `v1.0.0` no longer the latest release | tag `v1.0.1`, GitHub Release published |
| AUD-01 cannot recur | `test_clamd_directory_scan_reads_every_result_line` green in CI |
| Every GTK page builds in CI | `gtk-smoke` job constructs all six pages, settings, CSS, About |
| Version, metainfo and Flatpak manifest agree | `tests/test_packaging.py` green |
| Desktop behaviour verified by a human | validation records with PASS/FAIL and evidence |
| Package metadata valid | AppStream job green on the tag |

## 5. Out of scope

USB Auto-Scan (`v1.1.0`), Threat Intelligence (`v1.2.0`), realtime monitoring
(`v2.0.0`) and the residual AUD-14 hygiene items. Nothing in this release changes
the ClamAV integration beyond the AUD-01/AUD-04 fixes already merged by PR #13.
