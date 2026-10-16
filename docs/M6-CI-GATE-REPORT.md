# M6 CI & Quality Gate Report

**Date:** 2026-10-13 (revised by WO-1, same day)
**Branch:** `fix/pr5-audit-remediation` (remediation of PR #5, base `feature`)
**Baseline of this report:** `2955a0b`, the tip of the branch at the start of WO-1
**Commit under test:** the WO-1 working-tree change (uncommitted at the time of
writing — the object under review is `git diff`, which touches `uv.lock`,
`.github/workflows/ci.yml` and this report, and nothing else)
**Defects addressed:** `P2-DOC-05` from the independent audit of PR #5 — the audit
job was weaker than it appeared: `pip-audit` ran against the *CI environment*
(whose `pip`/`setuptools` had just been upgraded precisely so that the audit
would pass), without `--strict`, and without looking at `uv.lock` at all. WO-1
additionally closed a **live vulnerability finding** (`CVE-2026-104874`) that the
gate had never been able to report, because the gate had never actually run
(section 4).

> **Status: Phase 7 is CLOSED.** The gate has now actually run: CI run
> [`38493461942`](https://github.com/D3M-Sudo/ClamGuardian/actions/runs/38493461942)
> on commit `9832b4d`, job `Dependency audit (pinned runtime set)` — green, with
> `pip-audit --strict` reporting "No known vulnerabilities found" (section 5).
>
> **Phase 9 — the 1.0 release gate — remains OPEN** and is a separate gate, not
> covered by this report. See section 5 and `docs/ROADMAP.md`.

---

## 1. What CI runs now

> **Correction (WO-1).** The first revision of this report described the workflow
> below as "what CI runs now", while the file actually on the branch still
> contained the old `pip-audit` step and no `audit` job. The workflow is now
> **actually applied to the branch** by WO-1; the earlier text described a target
> state that had never been landed.

Triggers: every pull request, plus pushes to `main`, `feature`, `development`.
Permissions: `contents: read`.

### Job `test` (matrix: Python 3.11, 3.12, 3.13)

| Step | Command |
|---|---|
| Install GTK/PyGObject build dependencies | `apt-get install libgirepository-2.0-dev gir1.2-gtk-4.0 gir1.2-adw-1 libcairo2-dev pkg-config python3-dev meson ninja-build` |
| Install package and test dependencies | `python -m pip install --upgrade pip && python -m pip install '.[test,gtk]' ruff` |
| Lint | `ruff check .` |
| Type Check | `mypy clamguardian` |
| Test | `pytest` |

The `setuptools` upgrade is gone. It was introduced by commit `60bf0eb` on the
PR #5 branch for one stated reason — "*to ensure pip-audit passes cleanly without
flagging pre-installed runner build dependencies*" — that is, to make the audit
pass, not to build anything. Independent evidence that no build step needs it:

| Component | Build backend | Build requirements |
|---|---|---|
| `clamguardian` | `hatchling.build` | `["hatchling>=1.25"]` |
| `PyGObject` 3.58.1 (what `pip install '.[test,gtk]'` resolves) | `mesonpy` | `["meson-python>=0.12.1", "pycairo>=1.16"]` |
| `hatchling` 1.32.4 | `hatchling.ouroboros` | `[]` |

None of the three involves `setuptools`. `pip` is still upgraded so the runner
can build the wheel; that upgrade cannot influence the audit, which no longer
runs in this job.

### Job `audit` (single run, Python 3.11)

| Step | Command |
|---|---|
| Install uv and pip-audit | `python -m pip install --upgrade pip uv pip-audit` |
| Verify that `uv.lock` matches `pyproject.toml` | `uv lock --check` |
| Export the pinned runtime dependency set | `uv export --frozen --no-emit-project --format requirements-txt > requirements.lock.txt` |
| Audit the pinned runtime dependency set | `pip-audit --strict --progress-spinner off -r requirements.lock.txt` |

The project itself is never installed in this job, so nothing in that
environment can mask or change the audit outcome.

---

## 2. Why the audit is now meaningful

1. **Audited set = shipped set.** The audit reads the requirements exported from
   `uv.lock`, i.e. the pinned runtime closure, not whatever the CI runner happens
   to have installed. Upgrading `pip`/`setuptools` in the `test` job can no longer
   change (or hide) the audit outcome.
2. **`--strict`.** If a dependency cannot be collected or audited, the job fails
   instead of silently skipping it.
3. **Hashes.** The export carries hashes for every distribution, so `pip-audit`
   applies `--require-hashes` semantics: the audit is repeatable and a tampered
   artifact is a hard error.
4. **Lockfile discipline.** `uv lock --check` fails when `pyproject.toml` and
   `uv.lock` disagree. This is the check that would have caught the stale lock
   left behind when a dependency was removed from `pyproject.toml` alone.

### Perimeter declared explicitly

- Audited: the **runtime** dependency closure (13 distributions).
- Not audited: the CI toolchain and the `test`/`gtk` extras (development-only
  tooling does not ship to users).
- Not part of this gate: coverage thresholds, `ruff format --check` and `mypy` on
  the test suite. They were considered and deliberately left out: no coverage
  threshold is defined for the project yet, and the other two would add churn
  without a requirement to satisfy. They can be added when a threshold is agreed.

---

## 3. Reproduced locally

### 3.1 First revision of this report (historical, commit `7f8c1c2`)

Environment: Python 3.11.2, pytest 9.1.1, ruff and mypy from the same virtualenv,
uv 0.12.23.

```text
pytest -q           216 passed, 2 skipped in 1.81s
ruff check .        All checks passed!
mypy clamguardian   Success: no issues found in 26 source files
uv lock --check     Resolved 53 packages (exit 0: lockfile in sync)
```

The 2 skips are environmental and expected (PyGObject/GTK absent in a headless
run; CI installs GTK, so there they execute).

### 3.2 Re-run by WO-1 (branch tip `2955a0b` + the WO-1 change)

Environment: Python 3.11.2, pytest 9.1.1, ruff 0.17.0, mypy 2.4.0, uv 0.13.0,
pip-audit 2.10.1, actionlint 1.7.12. All commands were run on the working tree
under review.

```text
pytest -q                 228 passed, 2 skipped in 2.23s
ruff check .              All checks passed!
mypy clamguardian         Success: no issues found in 29 source files
uv lock --check           Resolved 54 packages (exit 0: lockfile in sync)
actionlint                exit 0 (repository-wide)
git diff --check          exit 0
```

`mypy` reports **29** source files rather than the 26 quoted by the first
revision of this report: the three `clamguardian/intelligence/` modules are kept
on this branch (unwired — nothing imports them; see `docs/ROADMAP.md`, Phase 11)
instead of being deleted, so the package count grew by three.

`actionlint` 1.7.12 was run over `.github/workflows/` and reports no findings, so
the edited workflow is syntactically and semantically valid for GitHub Actions
(shellcheck integration was not available in this environment). The audit gate
itself is covered in section 4.

**Export validated.** `uv export --frozen --no-emit-project --format requirements-txt`
produced a 682-line file; parsing it with `packaging.requirements` gives:

```text
requirements parsed : 13
all exactly pinned  : True
hashes present      : 646
packages            : aiohappyeyeballs, aiohttp, aiosignal, attrs, cffi, cryptography,
                      frozenlist, idna, multidict, propcache, pycparser,
                      typing-extensions, yarl
```

**CLI surface validated.** `pip-audit 2.10.1` exposes `-r/--requirement`,
`-S/--strict` and `--progress-spinner`; `uv lock --check` and
`uv export --frozen --no-emit-project --format requirements-txt` exist in
uv 0.12.23 and behave as used above.

## 4. The gate was executed — and it failed

### 4.1 The gate had never run

The first revision of this report said the gate was *verified by construction,
not by execution*. WO-1 established that the construction had never been executed
either:

- the `audit` job was **not in the workflow file** on the branch;
- there is **no CI run for this branch at all** — `gh run list` returns nothing
  for `fix/pr5-audit-remediation`, because the workflow triggers on pull requests
  and on pushes to `main`/`feature`/`development` only, and no pull request exists
  for this branch;
- the only run of this workflow lineage on the PR #5 head (`34688533042`) reports
  three `test` jobs and **no `audit` job**.

So no vulnerability scan of the shipped dependency set had ever happened.

### 4.2 Reproduction

`multidict` reaches the shipped runtime set by two independent paths, both rooted
in `aiohttp` — a declared core dependency (`pyproject.toml`) imported by
`clamguardian/databases/provider.py`:

```text
clamguardian -> aiohttp>=3.10 -> aiohttp 3.14.3 -> multidict        (direct)
                              -> aiohttp 3.14.3 -> yarl 1.24.5 -> multidict
```

`aiohttp 3.14.3` declares `multidict<7.0,>=4.5`; `yarl 1.24.5` declares
`multidict>=4.0`. The pin in `uv.lock` was **6.7.1**.

```text
$ uv export --frozen --no-emit-project --format requirements-txt > requirements.lock.txt
$ wc -l requirements.lock.txt
682
$ pip-audit --strict --progress-spinner off -r requirements.lock.txt
Found 1 known vulnerability in 1 package
Name      Version ID              Fix Versions
--------- ------- --------------- ------------
multidict 6.7.1   CVE-2026-104874 6.9.1
$ echo $?
1
```

The gate exits **1**. Had the `audit` job existed and run, the release candidate
would have been red.

### 4.3 Remediation

`uv lock --upgrade-package multidict` — the normal lockfile flow, no hand-edited
pins — resolved to **6.9.1**, the advisory's fix version and the highest release
satisfying `aiohttp`'s `multidict<7.0` constraint (6.8.0, 6.9.0, 6.9.1, 7.0.0 and
7.1.0 are all published; 7.x is **not** selectable here). Exactly one package
changed in `uv.lock`; nothing else moved:

```text
$ uv lock --upgrade-package multidict
Updated multidict v6.7.1 -> v6.9.1
$ diff <(git show HEAD:uv.lock | grep -E '^(name|version) = ') \
       <(grep -E '^(name|version) = ' uv.lock)
51c51
< version = "6.7.1"
---
> version = "6.9.1"
```

The exported runtime set changes by that single pin and nothing else, and the
pinned set is installable with hashes enforced:

```text
$ diff <(grep -oE '^[A-Za-z0-9_.-]+==[0-9][^ \\]*' before.txt) \
       <(grep -oE '^[A-Za-z0-9_.-]+==[0-9][^ \\]*' requirements.lock.txt)
9c9
< multidict==6.7.1
---
> multidict==6.9.1
$ pip install -r requirements.lock.txt      # fresh venv, hashes enforced
$ python -c "import aiohttp, multidict; print(aiohttp.__version__, multidict.__version__)"
3.14.3 6.9.1
```

`aiohttp` 3.14.3 imports and runs against `multidict` 6.9.1: the compatibility is
verified at runtime, not only against the declared constraint.

### 4.4 The gate now passes

```text
$ uv lock --check
Resolved 54 packages in 1ms                     # exit 0
$ pip-audit --strict --progress-spinner off -r requirements.lock.txt
No known vulnerabilities found                  # exit 0
```

## 5. CI evidence — obtained

The authoritative evidence for this gate now exists. The workflow was landed on
this branch (`9832b4d`) and the gate ran on the real runner:

| | |
|---|---|
| Run | [`38493461942`](https://github.com/D3M-Sudo/ClamGuardian/actions/runs/38493461942) — workflow `CI`, event `pull_request` |
| Commit | `9832b4d9fbbab97ad6ceb82b455067da616e3edb` |
| `Dependency audit (pinned runtime set)` | **pass** (26 s) — [job 115623792470](https://github.com/D3M-Sudo/ClamGuardian/actions/runs/38493461942/job/115623792470) |
| `test (3.11)` / `test (3.12)` / `test (3.13)` | **pass** — 247 tests each, 0 skipped |

Job log, verbatim:

```text
Verify that uv.lock matches pyproject.toml -> Resolved 54 packages in 1ms
Export the pinned runtime dependency set   -> uv export --frozen --no-emit-project --format requirements-txt > requirements.lock.txt
Audit the pinned runtime dependency set    -> pip-audit --strict --progress-spinner off -r requirements.lock.txt
                                           -> No known vulnerabilities found
```

**Phase 7 is therefore closed by execution, not by construction.** The earlier
obstacle recorded in the first revision of this report — GitHub rejecting a
workflow write from the automated credential for lack of the `workflows`
permission — was resolved by landing the change with a credential that holds it.

Two points that must not be conflated with that closure:

1. **CI runs 247 tests; the headless local run 228 + 2 skipped.** With
   GTK/PyGObject installed the GTK-dependent parametrisations execute, so the CI
   run is the more complete evidence. The 2 local skips are environmental.
2. **Phase 9 — the 1.0 release gate — is still open**, and it is *not* what this
   report covers. Still to be executed: build both Flatpak manifests, validate
   the metainfo with `appstreamcli`, scan with a real ClamAV, verify the GTK UI
   on a desktop session, run the release checklist, and create the `v1.0.0` tag
   the release manifest is pinned to. See `docs/ROADMAP.md`.

## 6. Follow-ups (not part of M6)

- **Documentation coherence (raised by WO-1).** `docs/ROADMAP.md` still marks
  Phase 7 `[COMPLETED]` and `README.md` still describes the `audit` job as already
  present. Neither matches the branch tip. Both must be corrected once the CI run
  is green; they were left untouched by WO-1, which is scoped to the M6 gate.
- Consider a scheduled (e.g. weekly) run of the `audit` job so newly disclosed
  CVEs surface between releases; it needs a documented triage path first.
- Revisit coverage thresholds when the project agrees on one.
- The `gtk` extra declares `PyGObject>=3.46` while the README claims `>= 3.53`
  (tracked with the remaining documentation items).
- The `audit` job writes `requirements.lock.txt` into the repository root; it is
  not in `.gitignore`, so a local run of the job leaves an untracked artifact.
  Consider ignoring it (not changed by WO-1, to keep the diff minimal).

---

## 7. How to reproduce

```bash
# the same commands the test job runs
pytest -q && ruff check . && mypy clamguardian

# the same commands the audit job runs (needs network access to PyPI and the
# vulnerability feed)
uv lock --check
uv export --frozen --no-emit-project --format requirements-txt > requirements.lock.txt
pip-audit --strict --progress-spinner off -r requirements.lock.txt

# validate the workflow itself
actionlint .github/workflows/ci.yml
```

If a TLS-intercepting proxy sits in front of PyPI, point the clients at the
system trust store instead of disabling verification: `UV_SYSTEM_CERTS=1` with
`SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt` for `uv`, and
`REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt` for `pip-audit`.

---

## 8. Appendix — the workflow change applied by this work order

This is now the **actual content of `.github/workflows/ci.yml`** in the working
tree prepared by WO-1, verified with `actionlint` 1.7.12 (exit 0). It supersedes
the earlier "proposed" appendix, which differed from the landed file in two ways:
it kept the `setuptools` upgrade, and it named the audit job differently.

It still has to be **landed**: committing and pushing a change under
`.github/workflows/` requires a credential holding the `workflows` permission,
which the automated credential in this environment does not have (section 5).

```yaml
name: CI

on:
  push:
    branches: [main, feature, development]
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.11", "3.12", "3.13"]
    steps:
      - name: Checkout
        uses: actions/checkout@v7
      - name: Install GTK/PyGObject build dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y libgirepository-2.0-dev gir1.2-gtk-4.0 gir1.2-adw-1 libcairo2-dev pkg-config python3-dev meson ninja-build
      - name: Set up Python
        uses: actions/setup-python@v7
        with:
          python-version: ${{ matrix.python-version }}
          cache: pip
      - name: Install package and test dependencies
        # `pip` is upgraded so the runner can build this project's wheel and
        # PyGObject. `setuptools` is deliberately NOT upgraded: neither
        # `hatchling` (this project's build backend) nor `meson-python`
        # (PyGObject's build backend) requires it, and upgrading it was the
        # workaround that used to make the old in-job audit pass. Dependency
        # auditing now runs in the dedicated `audit` job below, against the
        # pinned runtime dependency set.
        run: python -m pip install --upgrade pip && python -m pip install '.[test,gtk]' ruff
      - name: Lint
        run: ruff check .
      - name: Type Check
        run: mypy clamguardian
      - name: Test
        run: pytest

  audit:
    name: Dependency audit (pinned runtime set)
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v7
      - name: Set up Python
        uses: actions/setup-python@v7
        with:
          python-version: "3.11"
      - name: Install uv and pip-audit
        # Only the audit tooling is installed here. The project itself is never
        # installed in this job, so nothing in this environment can mask or
        # change the outcome of the audit.
        run: python -m pip install --upgrade pip uv pip-audit
      - name: Verify that uv.lock matches pyproject.toml
        run: uv lock --check
      - name: Export the pinned runtime dependency set
        run: uv export --frozen --no-emit-project --format requirements-txt > requirements.lock.txt
      - name: Audit the pinned runtime dependency set
        run: pip-audit --strict --progress-spinner off -r requirements.lock.txt
```

Diff summary against the workflow at the branch tip: the weak in-job
`pip-audit` step (no `-r`, no `--strict`, auditing the CI environment rather than
the shipped set) is removed from the `test` job; the `setuptools` upgrade that
step existed to satisfy is removed from the install step; a new `audit` job runs
`uv lock --check`, the lockfile export and
`pip-audit --strict -r requirements.lock.txt`. The triggers (`pull_request`, plus
pushes to `main`/`feature`/`development`) and the `contents: read` permissions are
unchanged, so a release pull request targeting `feature` runs the gate without any
trigger change. No `continue-on-error`, `|| true`, vulnerability exclusion or
severity downgrade is present anywhere in the file.
