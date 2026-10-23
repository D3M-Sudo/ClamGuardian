# CI hardening patch (AUD-05, AUD-07, AUD-13)

The branch is pushed by the `cline-cloud[bot]` GitHub App, which has no
`workflows` permission: GitHub rejects any push that touches
`.github/workflows/*`. The reviewed changes are therefore shipped as a plain
patch instead of being applied on the branch.
Applied in commit a3150827b96b3b7e36fe95d5c3e63b7286a21cda on 2026-10-20 (merged to `feature` as `144e89f`, PR #13); patch kept for traceability.

Apply from the repository root:

```bash
git apply --check docs/project/ci-hardening.patch
git apply docs/project/ci-hardening.patch
```

## Contents

- `release-gate.yml`: adds `permissions: contents: read`.
- Both workflows: `actions/checkout`, `actions/setup-python` and
  `actions/upload-artifact` pinned to commit SHAs (`v7`, `v7`, `v4`).
- Both workflows: the runner image is pinned to `ubuntu-24.04` instead of the
  moving `ubuntu-latest` label.
- `ci.yml`: pins `ruff==0.17.1`, `mypy==2.4.0`, `pytest==9.1.1`,
  `pytest-asyncio==1.4.0`, `PyYAML==6.0.3`.
- `ci.yml`: adds the `runtime-python` headless job on Python 3.14 (the
  interpreter shipped by `org.gnome.Sdk//51`).

## apt packages: accepted exception (AUD-13)

The GitHub-hosted runner image is mutable and apt package versions rotate out
of the Ubuntu mirrors. Pinning exact versions (`pkg=1.2.3-4ubuntu1`) makes CI
fail as soon as the image is refreshed or a mirror drops the build, so the
project pins the **image** (`ubuntu-24.04`) and keeps apt packages floating
inside that image. Full bit-for-bit reproducibility would require building in a
container referenced by digest; that is tracked as future work, not a blocker
for this PR.

Python tooling (ruff, mypy, pytest, pytest-asyncio, PyYAML) is pinned exactly,
so lint/type/test behaviour does not drift.

## Validation

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release-gate.yml'))"
```

The three pinned SHAs were resolved from the corresponding tags via the GitHub
API (`actions/checkout@v7` → `3d3c42e5`, `actions/setup-python@v7` →
`5fda3b95`, `actions/upload-artifact@v4` → `ea165f8d`).
