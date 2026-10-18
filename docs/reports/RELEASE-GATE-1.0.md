# ClamGuardian 1.0 — Release Gate Checklist (Phase 9)

**Release candidate:** `feature`
**Evidence collected on:** `8ee8a56ccbdcaa4bae964bcc57cd1b301b530be7` (the tagged commit; the earlier pass on `745e1e7` is kept below)
**Version:** `1.0.0` (`pyproject.toml` and `clamguardian.__version__`)
**Pass performed:** 2026-10-16 (CI, automated — Release Gate workflow)

> **Which commit to tag.** The tag `v1.0.0` was created on `3a3d172` and then
> force-moved twice: first to `745e1e7` after its tag run failed (section 3.1,
> run `38974145932`) with a `cffi` cp312 wheel left in the release manifest
> only, then to `8ee8a56` (the release docs commit) so the release ships the
> final documentation. Each position was validated by a green tag run
> (`38975655153`, then `38977065253`), and no artifact had ever been published
> from a stale position, so nothing consumed it.

> **Verdict: the gate is CLOSED.** The automated Release Gate
> (`.github/workflows/release-gate.yml`, 7 jobs) is green on the final tag run
> `38977065253` (`v1.0.0` @ `8ee8a56`): both Flatpak manifests built offline
> against `org.gnome.Platform//51`, AppStream validated, real ClamAV scans
> (clean + EICAR, via `clamscan` and `clamd`), GTK smoke passed, and the
> installable bundle `ClamGuardian-v1.0.0-linux-x86_64.flatpak` (~4.7 MB)
> published as a run artifact. The historic manual pass of 2026-10-15
> (candidate `26a9c14`) below is kept for the record: gates 8–11 were open
> there and are closed now by the automated runs.

---

## 1. Status at a glance

| # | Gate | Status | Evidence |
|---|---|---|---|
| 1 | CI green on the candidate commit | ✅ **VERIFIED** | run `38976889275` (push to `feature` @ `8ee8a56`); earlier passes §2.1 kept below |
| 2 | Lockfile in sync with `pyproject.toml` | ✅ **VERIFIED** | `uv lock --check` → exit 0 (54 packages) |
| 3 | Strict dependency audit of the shipped set | ✅ **VERIFIED** | `pip-audit --strict` → exit 0 |
| 4 | Test suite | ✅ **VERIFIED** | 251 passed (16 packaging) on `8ee8a56`; CI matrix 3.11/3.12/3.13 |
| 5 | Static analysis | ✅ **VERIFIED** | `ruff` clean, `mypy` clean (29 files) |
| 6 | Wheel build, install and end-to-end CLI run | ✅ **VERIFIED** | section 2.4 |
| 7 | Pinned runtime set installable with hashes enforced | ✅ **VERIFIED** | section 2.5 |
| 8 | **Flatpak builds (both manifests)** | ✅ **VERIFIED** | final tag run `38977065253` (`v1.0.0` @ `8ee8a56`): local + release manifests built offline against GNOME 51, first tag run `38974145932` failed on `cffi` cp312 in the release manifest only — fixed in `745e1e7` (see closing note 3.1), interim tag run `38975655153` green on that fix |
| 9 | **`appstreamcli validate` on the metainfo** | ✅ **VERIFIED** | final tag run `38977065253`, job `AppStream validation` green |
| 10 | **Scan with a real ClamAV (not a stub)** | ✅ **VERIFIED** | final tag run `38977065253`, job `Real ClamAV scan (clamscan + clamd)`: clean + EICAR detected via both backends |
| 11 | **GTK verification on a desktop session** | ✅ **VERIFIED (CI smoke)** | final tag run `38977065253`, job `GTK smoke test`: UI construction + database pages under Xvfb; a manual click-through on a real desktop remains a recommended — not blocking — follow-up |
| 12 | Documentation coherent with the artefacts | ✅ **VERIFIED** | this document, `../ROADMAP.md` (Phase 9 COMPLETED), `packaging/flatpak/README.md` |
| 13 | `v1.0.0` tag created and manifest pinned | ✅ **DONE** | tag `v1.0.0` → `8ee8a56` (`20e598a`), release manifest pinned to the tag; bundle artifact `ClamGuardian-v1.0.0-linux-x86_64.flatpak` (~4.7 MB) from final tag run `38977065253` |

---

## 2. Verified gates — evidence

### 2.1 CI on the candidate

```text
run 38496782061   event: push   headSha: 26a9c14b70330b421c95758fc1271073be5ad42f
                  status: completed   conclusion: success
  success  test (3.11)      success  test (3.12)
  success  test (3.13)      success  Dependency audit (pinned runtime set)
```

The audit job log, verbatim:

```text
Verify that uv.lock matches pyproject.toml -> Resolved 54 packages in 1ms
Export the pinned runtime dependency set   -> uv export --frozen --no-emit-project --format requirements-txt > requirements.lock.txt
Audit the pinned runtime dependency set    -> pip-audit --strict --progress-spinner off -r requirements.lock.txt
                                           -> No known vulnerabilities found
```

The earlier heads of the same lineage were green too: `df24e61` (run
`38494711827`), `9832b4d` (run `38493461942`), `74f789c` (run `38495196180`),
`8e430af` (run `38496501975`).

### 2.2 Lockfile and dependency audit, reproduced locally

```text
uv lock --check                                  exit 0  (Resolved 54 packages)
uv export --frozen --no-emit-project …           723 lines, sha256 13ac599159c3f9afc4a3aafef9d7347a0ebd1267f8c97e07864fba5419aeff64
pip-audit --strict --progress-spinner off -r …   exit 0  "No known vulnerabilities found"
```

`multidict` is pinned to `6.9.1` (`CVE-2026-104874` closed; the fix stays inside
`aiohttp`'s `multidict<7.0` constraint).

### 2.3 Test suite and static analysis

```text
pytest -q           228 passed, 2 skipped        (headless: the 2 skips are PyGObject/GTK)
ruff check .        All checks passed!
mypy clamguardian   Success: no issues found in 29 source files
actionlint          exit 0 (repository-wide)
git diff --check    exit 0
```

The 2 headless skips **do execute in CI**, which is why the CI run reports 247
tests and zero skips: with GTK installed the GTK-dependent parametrisations run.

### 2.4 Wheel build, install and end-to-end CLI

```text
python -m build --wheel --no-isolation
  -> clamguardian-1.0.0-py3-none-any.whl
     sha256 b984cbb90fcaf083a847d91435dc19035e2a83771c97358f54806cf15964888d
```

Contents verified: the `clamguardian` package, the `console_scripts` entry point
`clamguardian = clamguardian.cli.main:main`, and the three desktop-integration
files under `.data/data/share/`:

```text
share/applications/io.github.clamguardian.ClamGuardian.desktop
share/metainfo/io.github.clamguardian.ClamGuardian.metainfo.xml
share/icons/hicolor/scalable/apps/io.github.clamguardian.ClamGuardian.svg
```

The wheel was installed into a fresh virtualenv and the installed CLI was run end
to end **with a stub `clamscan` on `PATH`** (see 3.3 — there is no real ClamAV
here):

| Command | Observed | Exit |
|---|---|---|
| `clamguardian version` | `ClamGuardian 1.0.0` | 0 |
| `clamguardian profiles` | the four presets (`custom`, `full`, `home`, `quick`) | 0 |
| `clamguardian scan <file>` | `Status: CLEAN`, `Engine: clamscan`, `profile_id: default`, `sha256: …` | 0 |
| `clamguardian scan <file> --json` | JSON contract with `metadata.profile_id` and `metadata.sha256` | 0 |
| `clamguardian scan <directory>` | `CLEAN`, `profile_id` recorded, no `sha256` | 0 |
| `clamguardian scan <fifo>` | `Status: ERROR` — `Unsupported scan target: not a regular file or directory` | 3 |
| `clamguardian history list` | one row per scan | 0 |

A plain `pip install` of the wheel also installs the launcher, the AppStream
metadata and the icon under `share/`.

### 2.5 The pinned runtime set installs with hashes enforced

A fresh virtualenv built from the exported requirements file (hashes verified by
pip) imports cleanly:

```text
aiohttp 3.14.3   multidict 6.9.1   cryptography 50.0.1
```

### 2.6 Documentation

`docs/reports/M6-CI-GATE-REPORT.md` (Phase 7 closed by execution, Phase 9 called out as
open), `../ROADMAP.md` (Phase 7 evidence, Phase 9 remaining list, Phase 11
note), `docs/reports/M4-FINAL-REPORT.md` and `docs/reports/M5-HARDENING-REPORT.md` (scope-split
statements), `README.md` (CI paragraph and PyGObject requirement) are consistent
with the code and with the CI evidence. References to the deleted service
branches point at the annotated tag `audit/pr5-2026-10-12`.

---

## 3. Gates closed by the automated Release Gate (2026-10-16)

The historic 2026-10-15 manual pass below ("Not verified — why, and how to
close each one") is kept for the record. Each of its open gates was closed
by the Release Gate workflow (`.github/workflows/release-gate.yml`) on the
tag run `38977065253` (`v1.0.0` @ `8ee8a56`) — all 7 jobs green, bundle
`ClamGuardian-v1.0.0-linux-x86_64.flatpak` (~4.7 MB) and `gate-evidence.txt`
as run artifacts.

**Closing note — first tag run.** Run `38974145932` (tag on `3a3d172`)
failed in `flatpak-release` with `Failed to download sources … 404` on
`cffi-2.1.1-cp312-cp312-manylinux2014_x86_64.whl`: the cp312→cp314 platform
fix had landed only in the local manifest, and the release manifest — whose
sources CI never downloads until a tag exists — still carried the stale cp312
entry with a recycled URL. Fix `745e1e7`: `cffi` cp314 in **both** manifests,
plus two guard tests (`test_release_and_local_manifests_stay_in_sync`,
`test_binary_wheels_match_runtime_python`); the tag was then re-pointed to
the fixed commit and the re-run went green.

## 3b. Not verified — why, and how to close each one (historic, superseded)

All four gaps have the same root cause: this environment has **no root, no
`sudo`, and no Debian package sources** (the only apt repository configured is
`cli.github.com`), so no system package can be installed.
`apt-get install -s flatpak` answers: *"apt-get needs root privileges for real
execution"*. Everything below needs a real host or a proper CI runner.

### 3.1 Flatpak builds — both manifests

**Why it is open.** `flatpak`, `flatpak-builder`, `ostree` and the
`org.gnome.Platform` runtime are all absent, and they are system packages.

**How to close it**, on a Flatpak-capable host:

```bash
# development manifest (builds the working tree)
flatpak-builder --force-clean build-dir packaging/flatpak/io.github.clamguardian.ClamGuardian.local.yml
flatpak-builder --run build-dir packaging/flatpak/io.github.clamguardian.ClamGuardian.local.yml clamguardian version

# release manifest — only after the v1.0.0 tag exists (see section 4)
flatpak-builder --force-clean build-dir packaging/flatpak/io.github.clamguardian.ClamGuardian.yml
```

Note the ordering constraint: the release manifest is pinned to `tag: v1.0.0`,
so it cannot build before the tag is created. This is why the tag comes last.

### 3.2 `appstreamcli validate` on the metainfo

**Why it is open.** `appstreamcli` and `appstream-util` are absent;
libappstream is a system library with no PyPI distribution.

**How to close it:**

```bash
appstreamcli validate --no-net data/io.github.clamguardian.ClamGuardian.metainfo.xml
```

`tests/test_packaging.py` already enforces the structural invariants that the
validator checks (`id`, `launchable`, `releases`, `developer`, `content_rating`,
`summary`, `description`, licenses, homepage/bugtracker URLs), but a passing test
suite is **not** a substitute for the validator, and this checklist does not
claim otherwise.

### 3.3 Scan with a real ClamAV

**Why it is open.** `clamscan`, `clamdscan` and `freshclam` are absent. A source
build is not possible either: `cmake` is missing and **every** development header
probed is missing —

```text
/usr/include/openssl/ssl.h              ASSENTE
/usr/include/zlib.h                     ASSENTE
/usr/include/curl/curl.h                ASSENTE
/usr/include/json-c/json.h              ASSENTE
/usr/include/libxml2/libxml/parser.h    ASSENTE
pkg-config --list-all | wc -l           4
```

— and there is no way to install them. The end-to-end run in section 2.4 therefore
used a **stub `clamscan`** on `PATH`: it exercises the CLI, the profile
propagation, the SHA-256 recording, the special-target rejection and the history
persistence, but it does **not** exercise the real engine.

**How to close it**, on a host with ClamAV installed:

```bash
sudo apt-get install clamav
sudo freshclam

# a real detection
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt
clamguardian scan /tmp/eicar.txt          # expect: Status: INFECTED, exit 1

# the clamd path, which is the preferred one in the README
clamguardian scan /tmp/some-clean-file    # expect: Status: CLEAN, Engine: clamd, exit 0
```

Both paths matter: `P1-ENG-01` was specifically about the digest being recorded
only on the `clamscan` fallback and not on the `clamd` path, and the stub cannot
distinguish them.

### 3.4 GTK verification on a desktop session

**Why it is open.** PyGObject is not installed and cannot be built here: it needs
`libgirepository-2.0-dev`, `libcairo2-dev`, `gir1.2-gtk-4.0`, `gir1.2-adw-1` —
all system packages. There is also no display and no `Xvfb`.

What *is* covered: the UI module is import-safe headless (asserted by the suite),
and in CI the GTK-dependent parametrisations execute, which is why CI reports 247
tests and zero skips against 228 + 2 skipped locally. Nobody has opened the UI.

**How to close it**, on a desktop session:

```bash
python -m pip install '.[gtk]'
python -c "import clamguardian.ui.database_pages as m; print(m.__name__)"
# then launch the UI and exercise the database pages manually:
# add a source, update it, check the progress/refresh controls and the "Update all" button
```

---

## 4. The `v1.0.0` tag — DONE (procedure used)

The tag was created only after the automated gate evidence, then re-pointed
twice: to the fix commit (section 3) and finally to the release docs commit.
The commands actually run:

```bash
git tag -a v1.0.0 3a3d172 -m "ClamGuardian v1.0.0" && git push origin v1.0.0
# run 38974145932 failed (cffi cp312 in the release manifest only) →
# fix landed in 745e1e7 → tag force-moved (nothing had consumed the old tag):
git tag -f -a v1.0.0 745e1e7 -m "ClamGuardian v1.0.0 (gate-closed commit)" \
  && git push -f origin v1.0.0
# run 38975655153 green → the release docs landed in 8ee8a56 → tag force-moved
# again so the release ships the final documentation:
git tag -f -a v1.0.0 8ee8a56 -m "ClamGuardian v1.0.0: gate chiuso + docs (Phase 9 COMPLETED)" \
  && git push -f origin v1.0.0
```

Result: `v1.0.0` → `8ee8a56` (`20e598a`); final tag run `38977065253` all green
(`38975655153` was green on the intermediate position `745e1e7`).

> Note: the release manifest is pinned to the *tag* (`tag: v1.0.0`), per
> `packaging/flatpak/README.md`. Adding the resulting `commit:` alongside the
> tag remains a recommended hardening for a future Flathub submission —
> not a 1.0 gate item.

---

## 5. Promotion — DONE (executed 2026-10-17)

The release candidate lived on `feature`. The branching model is
`feature → testing → development → main`, and `main` is the release branch.
The promotion was executed as three merge commits, in order, with no
force-push and no content loss:

| PR | Path | Result |
|---|---|---|
| #9 | `feature` → `testing` | `testing` @ `a58155e` (2026-10-17) |
| #10 | `testing` → `development` | `development` @ `9cc4764` (2026-10-17) |
| #11 | `development` → `main` | `main` @ `ca887aa` (2026-10-17) |

After promotion all four branches converge on the 1.0 content (`feature`
remains the working tip at `8ee8a56`, where the tag sits).

Facts that matter for the record:

- `main` was **not** an ancestor of `feature` (merge-base `54cd4f19`), so each
  step was a merge commit (via PR), not a fast-forward — the same shape as
  PR #2/#3/#4.
- The content delta `main → feature` was **53 files, +10363 / −271, 40
  commits**; promoting could not lose content.
- `testing` and `development` required PR-only (0 reviews): merged directly.
  `main` requires 1 approving review; GitHub forbids self-approval and the
  author is the sole developer, so no eligible reviewer exists — PR #11 was
  merged with `--admin` (explicitly authorised by the author) after all
  required CI checks were green and the PR was `MERGEABLE`.
- Side effect: `.github/workflows/release-gate.yml` now also exists on `main`,
  so the `workflow_dispatch` trigger is available on the default branch.

---

## 6. How to re-run this checklist

```bash
# 1. CI on the candidate (must be green on the exact commit being released)
gh run list --repo D3M-Sudo/ClamGuardian --limit 5

# 2. the locally reproducible gates
uv lock --check
uv export --frozen --no-emit-project --format requirements-txt > requirements.lock.txt
pip-audit --strict --progress-spinner off -r requirements.lock.txt
pytest -q && ruff check . && mypy clamguardian
actionlint .github/workflows/ci.yml
git diff --check

# 3. wheel + end-to-end
python -m build --wheel --no-isolation
python -m venv /tmp/cg && /tmp/cg/bin/pip install dist/*.whl && /tmp/cg/bin/clamguardian version

# 4. the four gates that need a real host
#    -> sections 3.1, 3.2, 3.3, 3.4
```





