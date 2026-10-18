"""Quarantine key management for the desktop application.

The quarantine vault needs an AES-256 key on every run. The key is never
persisted by :class:`~clamguardian.core.quarantine.QuarantineVault` itself —
its storage is the caller's responsibility. This module owns that decision:

- try Secret Service (``libsecret``/GNOME Keyring) first,
- fall back to a ``0600`` key file in the app-data directory.

The module is import-safe on headless systems without PyGObject: Secret
Service access is exercised only on desktops; the key-file fallback works
everywhere.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..core.quarantine import _KEY_SIZE, QuarantineVault

#: Per-run quarantine key file name inside the app-data directory.
KEY_FILE_NAME = "quarantine-key"
#: Owner-only permissions for the key file.
KEY_FILE_MODE = 0o600
#: App-data subdirectory that holds the quarantine vault and its key.
QUARANTINE_DIR_NAME = "quarantine"


class QuarantineKeyManager:
    """Manage the persistent quarantine key for one app installation.

    On first run a fresh AES-256 key is generated and stored via Secret
    Service when available, else as a ``0600`` file under *key_dir*.
    Subsequent runs load the existing key from the same location so existing
    vault records stay decryptable.
    """

    def __init__(self, key_dir: Path) -> None:
        self._key_dir = Path(key_dir)
        self._key_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    @property
    def directory(self) -> Path:
        """Directory holding the quarantine key and the vault store."""
        return self._key_dir

    def load_or_create(self) -> bytes:
        """Return the existing quarantine key or generate and store a new one."""
        key = self._load()
        if key is not None:
            return key
        key = self._generate_and_store()
        return key

    # -- internals ---------------------------------------------------------

    def _key_path(self) -> Path:
        return self._key_dir / KEY_FILE_NAME

    def _load(self) -> bytes | None:
        """Try Secret Service first, then the key file."""
        key = self._load_secret_service()
        if key is not None:
            return key
        return self._load_file()

    def _load_secret_service(self) -> bytes | None:
        """Read the key from Secret Service (GNOME Keyring); ``None`` if absent."""
        try:  # pragma: no cover - requires libsecret on the desktop
            import gi

            gi.require_version("Secret", "1")
            from gi.repository import Secret

            password = Secret.password_lookup_sync(
                "clamguardian", "quarantine-key", None
            )
            if password is None:
                return None
            return bytes.fromhex(password)
        except Exception:  # noqa: BLE001 - Secret Service is optional
            return None

    def _store_secret_service(self, key: bytes) -> bool:
        """Store the key in Secret Service; ``False`` when unavailable."""
        try:  # pragma: no cover - requires libsecret on the desktop
            import gi

            gi.require_version("Secret", "1")
            from gi.repository import Secret

            Secret.password_store_sync(
                "clamguardian",
                "quarantine-key",
                key.hex(),
                None,
            )
            return True
        except Exception:  # noqa: BLE001 - Secret Service is optional
            return False

    def _load_file(self) -> bytes | None:
        path = self._key_path()
        if not path.is_file():
            return None
        try:
            raw = path.read_bytes()
            key = bytes.fromhex(raw.decode("ascii").strip())
        except (OSError, ValueError):  # corrupted or unreadable file
            return None
        if len(key) != _KEY_SIZE:
            return None
        return key

    def _store_file(self, key: bytes) -> None:
        path = self._key_path()
        path.write_text(key.hex())
        os.chmod(path, KEY_FILE_MODE)

    def _generate_and_store(self) -> bytes:
        key = QuarantineVault.generate_key()
        if not self._store_secret_service(key):
            self._store_file(key)
        return key
