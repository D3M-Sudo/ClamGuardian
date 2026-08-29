# ClamGuardian

[![CI](https://github.com/D3M-Sudo/ClamGuardian/actions/workflows/ci.yml/badge.svg)](https://github.com/D3M-Sudo/ClamGuardian/actions/workflows/ci.yml)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/License-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)

ClamGuardian is a Linux-first security framework built around ClamAV. It provides an asynchronous AV abstraction, encrypted quarantine, native GObject event signalling, and a dynamic threat-intelligence provider layer suitable for GTK4/Libadwaita applications and headless integrations.

## Architecture

```text
GTK4 / Libadwaita UI
        |
        v
ShieldTaskController (GObject signals)
        |
        v
ScanTaskRunner (bounded asyncio tasks)
        |
        v
BaseAVEngine <---- ClamAVEngine
                  |       |
            /run/clamd.ctl  clamscan/freshclam
                  |
          Flatpak: flatpak-spawn --host

Threat Intelligence
        |
ThreatProviderManager ---> VirusTotalProvider / external plugins

Security storage
        |
QuarantineVault ---> AES-256-GCM encrypted records
```

## Features

- **Hybrid ClamAV execution:** prefers `/run/clamd.ctl`, then falls back to `clamscan`/`freshclam` through `asyncio.subprocess`.
- **Flatpak-aware execution:** optionally routes host commands through `flatpak-spawn --host`.
- **Reactive event API:** `ShieldTaskController` emits `scan-started`, `scan-finished`, `threat-detected`, and `scan-cancelled` as native GObject signals.
- **Encrypted quarantine:** AES-256-GCM authenticated encryption, owner-only vault permissions, atomic writes, and integrity-protected metadata.
- **Extensible threat intelligence:** abstract `BaseThreatProvider`, dynamic Python entry-point discovery, and a VirusTotal v3 provider.
- **Async concurrency:** bounded multi-slot scan runner with cancellation support.
- **Python 3.11+:** typed, packaged with Hatchling, and tested by pytest.

## Installation

ClamGuardian targets Linux systems with Python 3.11 or newer. PyGObject requires the corresponding system GObject/GTK development packages.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install '.[test]'
```

On Debian/Ubuntu systems, install PyGObject prerequisites if pip needs to build it:

```bash
sudo apt-get update
sudo apt-get install -y libgirepository1.0-dev gir1.2-gtk-4.0 gir1.2-adw-1 libcairo2-dev pkg-config
```

A working ClamAV installation is required for real scans. The framework itself does not install or configure the antivirus daemon.

## Usage

### Scan with the hybrid engine

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

### Encrypted quarantine

The vault key must be supplied by the application. For production deployments, persist the key in an OS-backed secret store rather than a plaintext configuration file.

```python
from pathlib import Path
from clamguardian.core import QuarantineVault

key = QuarantineVault.generate_key()
vault = QuarantineVault(Path("~/.local/share/clamguardian/quarantine").expanduser(), key)
entry = vault.quarantine(Path("/path/to/suspicious-file"))
vault.restore(entry.item_id)
```

### VirusTotal

Supply the API key at runtime; never commit it to source control.

```python
import asyncio
from clamguardian.intelligence import VirusTotalProvider

provider = VirusTotalProvider(api_key="YOUR_API_KEY")
result = asyncio.run(provider.lookup_hash("0" * 64))
print(result)
```

### Dynamic providers

Third-party packages can expose a `clamguardian.threat_providers` entry point whose object is a `BaseThreatProvider` instance or subclass. The manager discovers these providers without hard-coding their modules.

## Third-party ClamAV Databases

ClamAV's official signatures, updated by `freshclam`, do not cover every threat feed. Security researchers and communities publish additional ClamAV-compatible signature databases, and ClamGuardian lets you manage them alongside the official one:

- **Official vs third-party:** the official database is owned by the ClamAV engine/freshclam and is never touched by ClamGuardian's database manager. Third-party sources are fully managed — downloaded, verified, installed, updated and removed by `DatabaseManager`.
- **Add:** from the UI (`Antivirus Databases → Third-party → Add database`) or programmatically via `DatabaseManager.add_source()`. A source requires an ID, a name, an HTTPS URL, a safe plain filename, and optionally a SHA-256 digest.
- **Update:** each row has an *Update* button (`await manager.update(source_id)`) and the page header offers *Update all* for every enabled, auto-update source (`await manager.update_enabled()`).
- **SHA-256 verification:** if a digest is provided, the downloaded artifact is hashed before installation; a mismatch aborts the update.
- **HTTPS only:** artifact URLs must use `https://`; plain HTTP is rejected by `DatabaseSource` validation.
- **Atomic install & rollback:** downloads go to a staging directory and are moved into place only after verification. If a step fails, the previously installed database files are restored from a backup, so scanning never loses its current signatures.
- **Enable / auto-update:** each source can be disabled individually or excluded from bulk updates, with the choice persisted in the manager state file and restored on the next launch.
- **Remove:** deleting a source also deletes its managed database files after an explicit confirmation dialog.

## GTK4 / Libadwaita UI

The database management flow is a real GTK4/Libadwaita navigation:

```text
Antivirus Databases
        |
        +-- ClamAV Official (managed by freshclam)
        |
        +-- Third-party
                |
                +-- Database rows (status, enable, auto-update, update, remove)
                +-- Add database (Adw.Dialog)
```

- `AntivirusDatabasesPage` is a `Adw.PreferencesPage` embedded in an `Adw.NavigationView`; the *Third-party* row pushes `ThirdPartyDatabasesPage`.
- `ThirdPartyDatabasesPage` lists one `Adw.ActionRow` per source with live status (Available / Installed / Disabled / Updating… / Update error), enable and auto-update switches, per-row update, and a confirmed remove via `Adw.AlertDialog`. An empty state (`Adw.StatusPage`) opens the add dialog directly.
- All operations run through an asyncio/GTK bridge (`run_async`) that never blocks the main loop; the UI always renders the real `DatabaseManager` state.
- The UI module is import-safe on headless systems: without PyGObject the page classes fail only when instantiated, so `pytest` works on CI without GTK.

```python
from clamguardian.ui import build_database_navigation
from clamguardian.databases import DatabaseManager

manager = DatabaseManager(db_dir, state_file)
view = build_database_navigation(manager)  # Adw.NavigationView, ready to embed
```

## Security model

- Quarantine data is authenticated and encrypted with AES-256-GCM.
- Each record uses a fresh 96-bit nonce.
- Metadata is authenticated as AES-GCM associated data, preventing undetected metadata tampering.
- Vault directories are created with `0700`; record and restored-file writes use `0600`.
- External commands are executed without a shell, reducing command-injection exposure.
- VirusTotal credentials are held in memory by the provider and are not written to disk.

## Testing and CI

Run the local test suite with:

```bash
pytest
```

Lint with:

```bash
ruff check .
```

GitHub Actions tests Python 3.11, 3.12, and 3.13 and installs the GTK/PyGObject system dependencies required by the package.

## Scope

This repository is the core framework. A complete desktop product can build its GTK4/Libadwaita presentation layer, portal permissions, service integration, USB monitoring, real-time/on-access monitoring, scan profiles, and operational policy on top of these primitives.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
