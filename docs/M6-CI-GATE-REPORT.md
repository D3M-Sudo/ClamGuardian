# M6 CI & Quality Gate Report

**Date:** 2026-10-13
**Branch:** `fix/pr5-audit-remediation` (remediation of PR #5, base `feature`)
**Commit under test:** the commit that introduces this report (see `git log`)
**Defect addressed:** `P2-DOC-05` from the independent audit of PR #5 — the audit
job was weaker than it appeared: `pip-audit` ran against the *CI environment*
(whose `pip`/`setuptools` had just been upgraded precisely so that the audit
would pass), without `--strict`, and without looking at `uv.lock` at all.

---

## 1. What CI runs now

Triggers: every pull request, plus pushes to `main`, `feature`, `development`.
Permissions: `contents: read` only.

### Job `test` (matrix: Python 3.11, 3.12, 3.13)

| Step | Command |
|---|---|
| Install GTK/PyGObject build dependencies | `apt-get install libgirepository-2.0-dev gir1.2-gtk-4.0 gir1.2-adw-1 libcairo2-dev pkg-config python3-dev meson ninja-build` |
| Install package and test dependencies | `python -m pip install --upgrade pip setuptools && python -m pip install '.[test,gtk]' ruff` |
| Lint | `ruff check .` |
| Type Check | `mypy clamguardian` |
| Test | `pytest` |

### Job `audit` (single run, Python 3.11)

| Step | Command |
|---|---|
| Install uv and pip-audit | `python -m pip install --upgrade pip uv pip-audit` |
| Verify that `uv.lock` matches `pyproject.toml` | `uv lock --check` |
| Export the pinned runtime dependency set | `uv export --frozen --no-emit-project --format requirements-txt > requirements.lock.txt` |
| Audit the pinned dependency set | `pip-audit --strict --progress-spinner off -r requirements.lock.txt` |

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

## 3. Reproduced locally on this commit

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

## 4. Not reproducible in this audit environment

`pip-audit` itself **could not be executed here**: auditing requires the
vulnerability feed, and this sandbox's egress proxy performs TLS interception
that the Python clients in the environment do not trust (the same limitation was
recorded in the PR #5 audit report for the pre-existing gate).
`pip-audit --dry-run -r ...` is not a workaround: it builds an isolated virtual
environment from the requirements file, which also needs the network.

Consequently the authoritative evidence for this gate is the `audit` job of the
CI run on this commit: it must show `uv lock --check` and
`pip-audit --strict -r requirements.lock.txt` both green. Until that run exists,
this gate is **verified by construction, not by execution** — the reviewer must
check the workflow run, not take the local output above as proof of a clean
vulnerability scan.

## 5. Follow-ups (not part of M6)

- Consider a scheduled (e.g. weekly) run of the `audit` job so newly disclosed
  CVEs surface between releases; it needs a documented triage path first.
- Revisit coverage thresholds when the project agrees on one.
- The `gtk` extra declares `PyGObject>=3.46` while the README claims `>= 3.53`
  (tracked with the remaining documentation items).

---

## 6. How to reproduce

```bash
# the same commands the test job runs
pytest -q && ruff check . && mypy clamguardian

# the same commands the audit job runs (needs network access to PyPI and the
# vulnerability feed)
uv lock --check
uv export --frozen --no-emit-project --format requirements-txt > requirements.lock.txt
pip-audit --strict --progress-spinner off -r requirements.lock.txt
```

---

## 7. Appendix — the proposed `.github/workflows/ci.yml`

The workflow change below is **not** part of the pushed branch: the automated
credential used for this remediation cannot update files under
`.github/workflows/` (GitHub rejects it with "refusing to allow a GitHub App to
create or update workflow ... without `workflows` permission"). Apply it with a
credential that has that permission, then verify the `audit` job result — the
gate stays *verified by construction* until that run exists.

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
        # pip/setuptools are upgraded only so the runner can build the wheel and
        # PyGObject. Dependency auditing runs in the dedicated `audit` job below
        # against the pinned lockfile, so nothing in this job can mask a finding.
        run: python -m pip install --upgrade pip setuptools && python -m pip install '.[test,gtk]' ruff
      - name: Lint
        run: ruff check .
      - name: Type Check
        run: mypy clamguardian
      - name: Test
        run: pytest

  audit:
    name: Dependency audit (pinned set)
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v7
      - name: Set up Python
        uses: actions/setup-python@v7
        with:
          python-version: "3.11"
      - name: Install uv and pip-audit
        run: python -m pip install --upgrade pip uv pip-audit
      - name: Verify that uv.lock matches pyproject.toml
        run: uv lock --check
      - name: Export the pinned runtime dependency set
        run: uv export --frozen --no-emit-project --format requirements-txt > requirements.lock.txt
      - name: Audit the pinned dependency set
        run: pip-audit --strict --progress-spinner off -r requirements.lock.txt
```

Diff summary against the previous workflow: `pip-audit` removed from the `test`
job; new `audit` job with `uv lock --check`, the lockfile export and
`pip-audit --strict -r`; comment added to the pip/setuptools upgrade step.
