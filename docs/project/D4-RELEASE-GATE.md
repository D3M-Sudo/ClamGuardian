# D4 release-gate patch — applied

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

Applied on the `1.0.1` release-engineering branch, on top of `feature` @
`4a3d165`. `git apply --check docs/project/D4-release-gate.patch` was clean
before applying, so the patch remains valid as a reference for the exact diff.

Committing `.github/workflows/*` requires a token with the `workflows`
permission: the `cline-cloud[bot]` app used for the automated branches does not
have it, so the workflow hunk must be committed by the maintainer (or any token
that carries that scope). The rest of the release-engineering change is
independent of it.

## Verification

- `git apply --check docs/project/D4-release-gate.patch` → exit 0 on `4a3d165`.
- The inline script builds `QuarantineKeyManager` and `SqliteHistoryStore` under
  `tempfile.mkdtemp()`, so it never touches the developer's real app data.
- `window.show_page()` is called for every id in `SIDEBAR_ENTRIES`; the assertion
  fails if a page is missing from the stack.
- The release artifact name follows the new version:
  `ClamGuardian-v1.0.1-linux-x86_64.flatpak`.

The patch file is kept for traceability, exactly like
`docs/project/ci-hardening.patch` (see `docs/project/CI-HARDENING.md`).
