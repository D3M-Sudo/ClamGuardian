# M7 Packaging Report (Phase 8)

**Date:** 2026-10-13
**Branch:** `fix/pr5-audit-remediation` (remediation of PR #5, base `feature`)
**Defects addressed:** `P1-DOC-03` (dangling icon reference, AppStream metadata that
could not validate) and `P2-DOC-04` (Flatpak manifest not pinned, no desktop
integration installed, incomplete `finish-args`) from the independent audit.

---

## 1. What was delivered

| Artifact | Change |
|---|---|
| `data/icons/hicolor/scalable/apps/io.github.clamguardian.ClamGuardian.svg` | the icon referenced by the desktop entry now exists (it did not exist at all before) |
| `data/io.github.clamguardian.ClamGuardian.metainfo.xml` | added `<developer>`, `<content_rating type="oars-1.1"/>`, `homepage`/`bugtracker`/`vcs-browser` URLs, `<categories>`; release entry aligned with the project version |
| `packaging/flatpak/io.github.clamguardian.ClamGuardian.yml` | release manifest: source pinned to the `v1.0.0` tag, desktop entry + metainfo + icon installed into `/app/share/...`, every `finish-arg` justified in a comment |
| `packaging/flatpak/io.github.clamguardian.ClamGuardian.local.yml` | development manifest: builds the working tree (`type: dir`) |
| `packaging/flatpak/README.md` | the two manifests, the pinning rule, the `finish-args` rationale and the open release-gate items |
| `pyproject.toml` | `[tool.hatch.build.targets.wheel.shared-data]` ships the desktop entry, metainfo and icon in the wheel; `pyyaml` added to the `test` extra (the packaging tests parse the manifests); `uv.lock` regenerated |
| `tests/test_packaging.py` | 12 release-gate tests (see below) |

## 2. The automated release gate

`tests/test_packaging.py` runs headless and in CI and fails when the packaging
metadata drifts apart. It checks:

- `pyproject.toml` version == `clamguardian.__version__`;
- the console script target is importable and callable;
- the desktop entry has `Name`, `Comment`, `Exec`, `Icon`, `Type`, `Categories`,
  with `Exec=clamguardian` matching the console script and `Icon=<app-id>`;
- **the icon file referenced by the desktop entry exists** and is well-formed XML;
- the metainfo `<id>` matches the desktop file stem, `<launchable>` points at the
  desktop file, and `<releases>` contains the declared project version;
- the metainfo carries `developer`, `content_rating`, `summary`, `description`,
  `metadata_license`, `project_license`, `homepage` and `bugtracker`;
- the wheel `shared-data` mapping is exactly source → destination and every
  source file exists;
- both Flatpak manifests: `app-id`, `command`, and the three desktop-integration
  install commands;
- the release manifest is pinned to a git tag or commit, the development manifest
  builds the working tree;
- `finish-args` cover what the code actually needs (flatpak-spawn, network,
  writable app-data directory).

---

## 3. Verification actually performed here

### Wheel build and contents

```text
python -m build --wheel --no-isolation   ->  clamguardian-1.0.0-py3-none-any.whl (hatchling 1.32.4)
```

Contents verified by opening the archive:

```text
clamguardian-1.0.0.data/data/share/applications/io.github.clamguardian.ClamGuardian.desktop
clamguardian-1.0.0.data/data/share/icons/hicolor/scalable/apps/io.github.clamguardian.ClamGuardian.svg
clamguardian-1.0.0.data/data/share/metainfo/io.github.clamguardian.ClamGuardian.metainfo.xml
clamguardian-1.0.0.dist-info/entry_points.txt  ->  clamguardian = clamguardian.cli.main:main
```

> A real defect was found and fixed while doing this: the first `shared-data`
> configuration was written destination → source and hatchling silently ignored
> it, producing a wheel with no desktop integration. Hatchling maps
> **source → destination**; the mapping is now pinned by a test and the wheel was
> rebuilt and re-inspected.

### Install and run the real artifact

The built wheel was installed into a fresh virtualenv, and the installed CLI was
run end to end with a stub `clamscan` on `PATH` (no ClamAV in this environment):

| Command | Observed |
|---|---|
| `clamguardian version` | `ClamGuardian 1.0.0`, exit 0 |
| `clamguardian profiles` | the four presets (`custom`, `full`, `home`, `quick`) |
| `clamguardian scan <file>` (stub reports OK) | `Status: CLEAN`, `Engine: clamscan`, **`profile_id: default`** and **`sha256: …`** recorded, exit 0 |
| `clamguardian scan <file> --json` | JSON contract including `metadata.profile_id` and `metadata.sha256` |
| `clamguardian scan <file>` (stub reports FOUND, exit 1) | `Status: INFECTED`, threat line, exit 1 |
| `clamguardian scan <directory>` | `CLEAN`, `profile_id` recorded, no `sha256` (correct for a directory) |
| `clamguardian scan <fifo>` | `Status: ERROR` — `Unsupported scan target: not a regular file or directory`, exit 3, no ClamAV invocation |
| `clamguardian history list` | one row per scan, with the `infected` status for the Eicar case |

The installed venv also received the three desktop-integration files under
`share/`, i.e. a plain `pip install` now installs the launcher, the AppStream
metadata and the icon.

### Quality gates on this commit

```text
pytest -q          228 passed, 2 skipped
ruff check .       All checks passed!
mypy clamguardian  Success: no issues found in 26 source files
uv lock --check    lockfile in sync (54 packages)
```

---

## 4. Not verified — and what it needs

| Item | Why it is unverified here | What closes it |
|---|---|---|
| `appstreamcli validate` on the metainfo | the tool is not installed in this environment and the sandbox cannot install distribution packages | run it in the release gate environment; the structural invariants it checks are covered by `tests/test_packaging.py` |
| A real `flatpak-builder` run | `flatpak-builder`, an ostree repository and a Flatpak runtime are absent | build both manifests in a Flatpak-capable environment |
| Offline build backend | Flathub builds without network, while `pip install .` with build isolation tries to download `hatchling` | add a `python3-hatchling` module or vendor the wheel (recorded in `packaging/flatpak/README.md`) |
| ClamAV inside the sandbox | `clamscan`/`clamd`/`freshclam` are not installed; the CLI was exercised against a stub | run the packaged app on a host with ClamAV |
| Restoring a quarantined file to the host | `--filesystem=host:ro` is read-only, so restoring to an arbitrary host path needs a portal or a narrower writable path | decide the restore policy in the release gate |
| The `v1.0.0` tag referenced by the release manifest | it is created by the 1.0 release gate (Phase 9), not before | create the tag when cutting the release, then add the resulting `commit` to the manifest |

---

## 5. How to reproduce

```bash
python -m pytest -q tests/test_packaging.py
python -m build --wheel --no-isolation && python -c "import zipfile,glob;print(zipfile.ZipFile(glob.glob('dist/*.whl')[0]).namelist())"
python -m venv /tmp/cg && /tmp/cg/bin/pip install dist/*.whl && /tmp/cg/bin/clamguardian version
```
