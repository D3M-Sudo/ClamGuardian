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
import tempfile
from pathlib import Path

from ..core.quarantine import _KEY_SIZE, QuarantineVault
from ..history.backend import default_history_db_path

#: Per-run quarantine key file name inside the app-data directory.
KEY_FILE_NAME = "quarantine-key"
#: Owner-only permissions for the key file.
KEY_FILE_MODE = 0o600
#: App-data subdirectory that holds the quarantine vault and its key.
QUARANTINE_DIR_NAME = "quarantine"
#: Secret Service schema and lookup attributes (never contain the secret).
SECRET_SCHEMA_NAME = "io.github.clamguardian.Quarantine"
SECRET_ATTRIBUTES = {"purpose": "quarantine-key"}
#: Human-readable label shown by the keyring UI.
SECRET_LABEL = "ClamGuardian quarantine key"


def default_quarantine_dir() -> Path:
    """Resolve the quarantine app-data directory.

    The key and the vault live in ``<app-data>/quarantine``, i.e. a sibling
    of ``history.db`` under the same XDG data directory. The result is always
    a *directory*: :class:`QuarantineKeyManager` creates it on construction,
    so passing the history database file path here would raise
    :class:`FileExistsError`.
    """
    return default_history_db_path().parent / QUARANTINE_DIR_NAME


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

            schema = Secret.Schema.new(
                SECRET_SCHEMA_NAME,
                Secret.SchemaFlags.NONE,
                {"purpose": Secret.SchemaAttributeType.STRING},
            )
            password = Secret.password_lookup_sync(schema, dict(SECRET_ATTRIBUTES), None)
            return _decode_key(password)
        except Exception:  # noqa: BLE001 - Secret Service is optional
            return None

    def _store_secret_service(self, key: bytes) -> bool:
        """Store the key in Secret Service; ``False`` when unavailable."""
        try:  # pragma: no cover - requires libsecret on the desktop
            import gi

            gi.require_version("Secret", "1")
            from gi.repository import Secret

            schema = Secret.Schema.new(
                SECRET_SCHEMA_NAME,
                Secret.SchemaFlags.NONE,
                {"purpose": Secret.SchemaAttributeType.STRING},
            )
            return bool(
                Secret.password_store_sync(
                    schema,
                    dict(SECRET_ATTRIBUTES),
                    Secret.COLLECTION_DEFAULT,
                    SECRET_LABEL,
                    key.hex(),
                    None,
                )
            )
        except Exception:  # noqa: BLE001 - Secret Service is optional
            return False

    def _load_file(self) -> bytes | None:
        path = self._key_path()
        if not path.is_file():
            return None
        try:
            raw = path.read_text(encoding="ascii").strip()
        except OSError as exc:
            raise ValueError(f"Cannot read quarantine key file: {path}") from exc
        except UnicodeDecodeError as exc:
            raise ValueError("Quarantine key file is corrupt; refusing to rotate it") from exc
        key = _decode_key(raw)
        if key is None:
            # Rotating silently here would orphan every existing vault record.
            raise ValueError("Quarantine key file is corrupt; refusing to rotate it")
        return key

    def _store_file(self, key: bytes) -> None:
        """Write the key atomically with owner-only permissions from creation."""
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{KEY_FILE_NAME}.", dir=self._key_dir
        )
        tmp = Path(temporary)
        try:
            os.fchmod(descriptor, KEY_FILE_MODE)
            with os.fdopen(descriptor, "w", encoding="ascii") as handle:
                handle.write(key.hex())
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._key_path())
        finally:
            tmp.unlink(missing_ok=True)

    def _generate_and_store(self) -> bytes:
        key = QuarantineVault.generate_key()
        if not self._store_secret_service(key):
            self._store_file(key)
        return key


def _decode_key(value: str | None) -> bytes | None:
    """Decode a hexadecimal key, returning ``None`` when it is not 32 bytes."""
    if not value:
        return None
    try:
        key = bytes.fromhex(value.strip())
    except (TypeError, ValueError):
        return None
    return key if len(key) == _KEY_SIZE else None
