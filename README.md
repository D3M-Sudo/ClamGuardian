# ClamGuardian

> On-demand antivirus scanning for Linux desktops and servers — powered by ClamAV, with a GTK4 app, a scriptable CLI, and an encrypted quarantine vault.

[![CI](https://github.com/D3M-Sudo/ClamGuardian/actions/workflows/ci.yml/badge.svg)](https://github.com/D3M-Sudo/ClamGuardian/actions/workflows/ci.yml)
[![Release Gate](https://github.com/D3M-Sudo/ClamGuardian/actions/workflows/release-gate.yml/badge.svg)](https://github.com/D3M-Sudo/ClamGuardian/actions/workflows/release-gate.yml)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/License-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Code style: ruff](https://img.shields.io/badge/lint-ruff-261230.svg)](https://github.com/astral-sh/ruff)

> **Latest published release: v1.0.1** (2026-10-24, tag `v1.0.1`). The GitHub
> release includes a Flatpak artifact. The release description states that
> desktop validation preceded publication; however, the checked-in D4 session
> record remains `PENDING`, so this repository does not retain that manual-test
> evidence. See [`docs/reports/RELEASE-1.0.1.md`](docs/reports/RELEASE-1.0.1.md).
>
> **Security note:** `v1.0.0` is affected by AUD-01 — a directory scan served by
> `clamd` could report `clean` for a directory that contains an infected file.
> The fix is included in published `v1.0.1`. Later USB, realtime and VirusTotal
> integration changes on `feature` are not implied to be part of that release.
> Details and reporting process: [`SECURITY.md`](SECURITY.md).

## Contents

- [Highlights](#highlights)
- [Quick start](#quick-start)
- [Install](#install)
- [Usage (CLI)](#usage-cli)
- [Desktop app (GTK4)](#desktop-app-gtk4)
- [Third-party databases](#third-party-signature-databases)
- [Library API](#library-api)
- [Security model](#security-model)
- [Developing](#developing)
- [Roadmap & scope](#roadmap--scope)
- [Documentation map](docs/README.md)
- [License](#license)

## Highlights

| | What you get |
|---|---|
| 🛡️ | **Reliable detection through ClamAV** — prefers the fast `clamd` daemon, automatically falls back to `clamscan` |
| ⚡ | **Scan profiles** — one-click presets (`quick`, `home`, `full`, `custom`) shared by the app and the CLI |
| 🔒 | **Encrypted quarantine** — detected files are locked away with AES-256-GCM authenticated encryption |
| 🖥️ | **Native GTK4 desktop app** — scan, history, quarantine and extra signature databases in one place |
| ⌨️ | **Scriptable CLI** — human and `--json` output, stable exit codes, clean Ctrl+C cancellation |
| 📦 | **Flatpak-first install** — sandboxed app that reaches your host ClamAV safely |
| 🧪 | **Tested & gated** — full pytest suite, lint, type checks and an automated release gate |
| 🔌 | **Optional automation** — removable-media scanning, realtime monitoring, scheduled scans and user-session autostart |
| 🌐 | **Optional VirusTotal intelligence** — explicit Public/Premium profiles, hash-first lookup and separately consent-gated file submission; Public remains administratively blocked pending written eligibility authorization |

## Quick start

Install the Flatpak bundle attached to the intended GitHub release and run your first scan:

```bash
flatpak install --user ./ClamGuardian-vX.Y.Z-linux-x86_64.flatpak
flatpak run io.github.clamguardian.ClamGuardian
```

You'll need ClamAV installed on the host (`clamscan`, `freshclam`, optionally the
`clamd` daemon) — the app reaches it through the sandbox — and the GNOME
Platform 51 runtime, pulled automatically from Flathub on first run.

> Release artifacts are immutable snapshots and may not contain the latest `feature` changes. Check the release notes and the source tag attached to the bundle before deployment. The v1.0.0 release is affected by AUD-01; the fix is present in later source history as described above.

## Install

### Flatpak (recommended)

See [Quick start](#quick-start) — one bundle, one command.

### From source

Core dependencies are intentionally minimal (`cryptography`, `aiohttp`): PyGObject
lives in the optional `[gtk]` extra, so headless machines install and test without
building GTK bindings. A `uv.lock` is provided for reproducible environments.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install '.[test]'        # headless (core + tests)
python -m pip install '.[test,gtk]'    # full desktop (adds PyGObject >= 3.46)
```

<details>
<summary>Debian/Ubuntu GTK build prerequisites</summary>

```bash
sudo apt-get update
sudo apt-get install -y libgirepository-2.0-dev gir1.2-gtk-4.0 gir1.2-adw-1 libcairo2-dev pkg-config python3-dev meson ninja-build
```

> Versions of PyGObject 3.53+ require the `girepository-2.0` bindings
> (`libgirepository-2.0-dev` above).

</details>

<details>
<summary>Locked environments with uv</summary>

```bash
uvx --with '.[test]' pytest            # headless CI path
uvx --with '.[test,gtk]' pytest        # full GTK path
```

</details>

A working ClamAV installation is required for real scans. ClamGuardian itself does
not install or configure the antivirus daemon.

## Usage (CLI)

Installing the package provides the `clamguardian` command (also `python -m clamguardian.cli`).
It drives the exact same core as the desktop app — profiles resolve from one registry,
scans run through one runner, one engine.

```bash
clamguardian scan PATH                     # scan a file or directory
clamguardian scan PATH --profile quick     # quick / home / full / custom
clamguardian scan PATH --json              # machine-readable report on stdout
clamguardian profiles [--json]             # list the available profiles
clamguardian version
```

Without `--profile`, the built-in default (*Standard Scan*) is used.

```text
$ clamguardian scan ~/Downloads --profile quick
ClamGuardian
Profile: Quick Scan
Target: /home/user/Downloads
Scanning...
Scan completed
Status: CLEAN
Engine: clamscan
Duration: 2.41s
```

<details>
<summary>JSON output contract</summary>

`scan --json` prints exactly one JSON object on stdout (diagnostics go to stderr),
with deterministic keys:

```json
{
  "status": "clean",
  "profile": "quick",
  "target": "/home/user/Downloads",
  "engine": "clamscan",
  "threats": [],
  "files_scanned": 0,
  "duration_seconds": 2.41,
  "error": null,
  "metadata": {"profile_id": "quick"}
}
```

</details>

### Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | scan completed / clean |
| 1 | threats detected |
| 2 | usage / argument error |
| 3 | engine or runtime error |
| 4 | scan timeout |
| 5 | scan cancelled (Ctrl+C) |
| 6 | `doctor`: one or more critical scan dependencies are missing |

Pressing **Ctrl+C** during a scan shuts the ClamAV subprocess group down cleanly
(`SIGTERM`, then `SIGKILL` after a grace period) and exits with code 5 — no
zombies, no orphans.

### Optional automation and threat intelligence

The following commands configure optional user preferences. USB, realtime and
scheduled services are managed by the GTK application lifecycle; autostart is a
user-session desktop entry and is not a privileged system service. These
features are present on the current `feature` branch. The published Flatpak
artifact remains tied to the immutable release tag named in the release manifest.

```bash
clamguardian usb status
clamguardian usb enable
clamguardian usb disable
clamguardian monitor status
clamguardian monitor enable
clamguardian monitor add DIRECTORY
clamguardian monitor remove DIRECTORY
clamguardian schedule status
clamguardian schedule enable --time 02:00
clamguardian schedule disable
clamguardian autostart status
clamguardian autostart enable
clamguardian autostart disable
```

VirusTotal hash lookup is the default. Public and Premium profiles use separate
credentials stored only in the OS Secret Service. The Public API remains blocked
until written VirusTotal eligibility clarification is recorded; Premium requires
a valid Premium entitlement. No profile fallback is performed.

```bash
clamguardian intel profile premium
clamguardian intel set-key --profile premium
clamguardian intel status
clamguardian intel enable
clamguardian intel lookup SHA256
clamguardian intel upload /path/to/file
```

The upload command performs a hash lookup first. If no report exists, it shows
the file metadata and privacy warning, then requires typing `UPLOAD` before
transmitting file contents. The GTK Settings page provides equivalent profile,
credential and consent-gated upload controls. Never submit sensitive or
confidential files. VirusTotal may retain, analyze and share submitted samples
under its policies.

**Important:** Public API requests remain blocked by a maintainer-controlled
eligibility gate until written VirusTotal clarification and ClamGuardian's
product/use-case eligibility are recorded. Premium access is separately
license-dependent. Enabling the preference or storing a key does not bypass
either provider's authorization requirements. No legal or terms-compliance
conclusion is implied.

## Desktop app (GTK4)

The desktop app wraps the same core in a native GTK4/Libadwaita interface:

- **Scan** — pick a target and a profile, follow the in-flight state and review the result; detected files can be moved to the encrypted quarantine directly from the threat list
- **History** — filtered list with purge, profile and SHA-256 per scan, detail dialog
- **Quarantine** — encrypted detections with detail view, restore and delete
- **Databases** — official signatures (owned by `freshclam`) plus manageable third-party sources (see below)
- **Diagnostics** — dependency checks with per-distro remedies, presented at first run when a critical dependency is missing
- **Settings** — default scan profile, desktop notifications and system/light/dark theme, plus optional automation switches (USB, realtime, scheduled scans and autostart)

Scan-completion notifications can be disabled in Settings and are content-free:
they report the status and the number of files/threats, never file names or
paths. The app follows the system theme by default and ships a small accent
stylesheet; no colour is forced on the user. Quarantine, history and settings
live in the application-data directory, both outside and inside the Flatpak
sandbox.

The UI is import-safe on headless systems: without PyGObject the GTK pages
simply cannot be instantiated, so the test suite runs anywhere.

```python
from clamguardian.ui import build_database_navigation
from clamguardian.databases import DatabaseManager

manager = DatabaseManager(db_dir, state_file)
view = build_database_navigation(manager)  # Adw.NavigationView, ready to embed
```

## Third-party signature databases

The official ClamAV signatures (updated by `freshclam`) don't cover every
threat feed. ClamGuardian lets you add community ClamAV-compatible databases
alongside the official one:

| Action | How |
|---|---|
| **Add** | In the app: *Antivirus Databases → Third-party → Add database*; needs a name, an HTTPS URL, a filename and a SHA-256 digest |
| **Update** | Per-row *Update* button, or *Update all* in the page header for enabled auto-update sources |
| **Verify** | Downloaded files are hash-checked before install; a mismatch aborts the update |
| **Install safely** | Downloads land in a staging folder and move into place only after verification — a failure restores the previous signatures |
| **Manage** | Each source can be disabled or excluded from bulk updates; removal also deletes its files after confirmation |

All downloads require HTTPS and all operations run through the asyncio/GTK
bridge (`run_async`), so the interface never freezes.

## Library API

For developers embedding ClamGuardian (headless services, custom front-ends):

```python
import asyncio
from pathlib import Path
from clamguardian.engines import ClamAVEngine

async def main() -> None:
    engine = ClamAVEngine()
    result = await engine.scan(Path.home() / "Downloads")
    print(result.clean, result.threats, result.engine)

asyncio.run(main())
```

```python
from pathlib import Path
from clamguardian.core import QuarantineVault

key = QuarantineVault.generate_key()   # persist in an OS-backed secret store, never plaintext
vault = QuarantineVault(Path("~/.local/share/clamguardian/quarantine").expanduser(), key)
entry = vault.quarantine(Path("/path/to/suspicious-file"))
vault.restore(entry.item_id)
```

## Security model

| Guarantee | How |
|---|---|
| Authenticated quarantine | AES-256-GCM with a fresh 96-bit nonce per record |
| Tamper-evident metadata | metadata sealed as AES-GCM associated data |
| Owner-only storage | vault dirs `0700`, record and restored files `0600` |
| No shell, no injection | external commands run without a shell |
| VirusTotal egress gate | hash lookup is opt-in; Public requests remain blocked pending written eligibility authorization; optional file submission requires a fresh absent-hash result and explicit per-file consent; ClamAV verdicts remain unchanged |
| Known issue in 1.0.0 | AUD-01: `clamd` directory scans could miss an infected file after a clean one; fixed in 1.0.1 — see [`SECURITY.md`](SECURITY.md) |
| Sandboxed desktop app | Flatpak manifest grants only what the app needs (host ClamAV via `flatpak-spawn`, read-only host FS, app-data dir) |

## Developing

```bash
pytest            # full test suite
ruff check .      # lint
mypy clamguardian # type checks
```

- **CI** (`.github/workflows/ci.yml`) runs on every PR and on pushes to `main`,
  `feature` and `development`: tests on Python 3.11–3.13, a headless
  `runtime-python` job on Python 3.14 (the Flatpak SDK interpreter), plus a strict
  dependency audit of the pinned lockfile (`uv lock --check`, `pip-audit --strict`).
- **Release gate** (`.github/workflows/release-gate.yml`) builds both Flatpak
  manifests offline against GNOME Platform 51, validates AppStream metadata, runs
  real ClamAV scans and a GTK smoke test, and uploads installable bundles
  (kept 14 days; the release bundle 90 days). Opening a `feature → testing`
  promotion PR also builds a testable `ClamGuardian-testing-…flatpak` bundle.
  Evidence: `docs/reports/RELEASE-GATE-1.0.md`.

## Branching model

Development flows `feature → testing → development → main`:

| Branch | Role | Protection |
|---|---|---|
| `feature` | Active development | open |
| `testing` | Integration and QA | PR-only, no force push/delete |
| `development` | Stable pre-release | PR-only, no force push/delete |
| `main` | Production; releases are cut from here | ruleset `main-protection`: PR required (0 approvals), thread resolution, no delete/force-push, no bypass |

## Roadmap & scope

This repository contains the GTK desktop application, ClamAV scanning core,
third-party signature database management, removable-media automation,
realtime monitoring, scheduled scans, user-session autostart and optional
VirusTotal intelligence. The automation and intelligence subsystems have been
merged to `feature`; their presence does not by itself mean they are enabled or
release-promoted. VirusTotal Public API access remains administratively blocked
pending written eligibility authorization. See [`docs/ROADMAP.md`](docs/ROADMAP.md)
for milestone status and [`docs/README.md`](docs/README.md) for the documentation
map, including design, security, validation and historical reports.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).


