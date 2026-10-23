# D4 release-gate patch — applyable patch

## What this is

Phase D4 extended the desktop application to every page (History, Quarantine,
Databases, Diagnostics, Settings) plus Settings, the stylesheet and the About
dialog. The widget tests already run in the CI `test` job under Xvfb, but the
`gtk-smoke` job of the release gate only constructed the database pages, the app
shell, the Diagnostics page and the Scan page.

`docs/project/D4-release-gate.patch` closes that gap: the job now builds the
whole `MainWindow` with an isolated settings store, history store and quarantine
key manager, walks every sidebar page, loads the packaged stylesheet and builds
the About dialog.

## Status

Prepared as `docs/project/release-gate-1.0.1.patch` on top of `feature` @
`4a3d165`. It supersedes the older `D4-release-gate.patch` (same smoke script)
and adds the 1.0.1 release artifact name.

Why a patch: committing `.github/workflows/*` requires a token with the
`workflows` permission. The `cline-cloud[bot]` app used for the automated
branches does not have it — the push was rejected with:

```
refusing to allow a GitHub App to create or update workflow
`.github/workflows/release-gate.yml` without `workflows` permission
```

Apply it from the repository root with a token that carries the scope:

```bash
git apply --check docs/project/release-gate-1.0.1.patch
git apply docs/project/release-gate-1.0.1.patch
git commit -am "ci: construct every desktop page in the release-gate GTK smoke"
```

Versions are documented in
[`../reports/RELEASE-1.0.1.md`](../reports/RELEASE-1.0.1.md).

## Verification

- `git apply --check docs/project/release-gate-1.0.1.patch` → exit 0 on
  `4a3d165`.
- The inline script was syntax-checked (`py_compile`) after extraction from the
  YAML block scalar (59 lines).
- The inline script builds `QuarantineKeyManager` and `SqliteHistoryStore` under
  `tempfile.mkdtemp()`, so it never touches the developer's real app data.
- `window.show_page()` is called for every id in `SIDEBAR_ENTRIES`; the assertion
  fails if a page is missing from the stack.
- The release artifact name follows the new version:
  `ClamGuardian-v1.0.1-linux-x86_64.flatpak`.

The patch file is kept for traceability, exactly like
`docs/project/ci-hardening.patch` (see `docs/project/CI-HARDENING.md`).
