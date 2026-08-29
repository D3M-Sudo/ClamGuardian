"""Encrypted quarantine vault using AES-256-GCM."""

from __future__ import annotations

import json
import os
import secrets
import stat
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_MAGIC = b"CLAMGUARDIAN-Q1\x00"
_NONCE_SIZE = 12
_KEY_SIZE = 32


@dataclass(frozen=True, slots=True)
class QuarantineEntry:
    """Metadata describing one encrypted quarantine object."""

    item_id: str
    original_name: str
    original_path: str
    created_at: float
    size: int


class QuarantineVault:
    """Store quarantined files as authenticated AES-256-GCM ciphertext.

    The caller owns the 32-byte master key. Keys are deliberately never persisted by
    this class; applications should obtain them from a secure OS keyring or secret
    store. Vault files are created with owner-only permissions.
    """

    def __init__(self, directory: Path, key: bytes) -> None:
        if len(key) != _KEY_SIZE:
            raise ValueError("Quarantine key must be exactly 32 bytes (AES-256)")
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._harden_permissions(self.directory)
        self._aes = AESGCM(key)

    @staticmethod
    def generate_key() -> bytes:
        """Generate a cryptographically secure AES-256 key."""
        return secrets.token_bytes(_KEY_SIZE)

    def quarantine(self, source: Path) -> QuarantineEntry:
        """Encrypt *source* into the vault and remove the original after success."""
        source = Path(source).resolve(strict=True)
        if not source.is_file():
            raise ValueError("Only regular files can be quarantined")
        item_id = uuid.uuid4().hex
        created_at = __import__("time").time()
        plaintext = source.read_bytes()
        metadata = {
            "item_id": item_id,
            "original_name": source.name,
            "original_path": str(source),
            "created_at": created_at,
            "size": len(plaintext),
        }
        aad = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
        nonce = secrets.token_bytes(_NONCE_SIZE)
        ciphertext = self._aes.encrypt(nonce, plaintext, aad)
        destination = self.directory / f"{item_id}.qtn"
        payload = _MAGIC + len(aad).to_bytes(4, "big") + aad + nonce + ciphertext
        self._atomic_write(destination, payload)
        try:
            source.unlink()
        except OSError:
            destination.unlink(missing_ok=True)
            raise
        return QuarantineEntry(**metadata)

    def restore(self, item_id: str, destination: Path | None = None) -> Path:
        """Decrypt an item into *destination* and remove its quarantine record."""
        record = self._read(item_id)
        metadata, nonce, ciphertext = record
        aad = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
        plaintext = self._aes.decrypt(nonce, ciphertext, aad)
        target = Path(destination) if destination is not None else Path(metadata["original_path"])
        target = target.expanduser()
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._atomic_write(target, plaintext, mode=0o600)
        self._path(item_id).unlink()
        return target

    def delete(self, item_id: str) -> None:
        """Permanently remove an encrypted quarantine item."""
        self._path(item_id).unlink(missing_ok=False)

    def list_entries(self) -> list[QuarantineEntry]:
        """Return metadata for all valid quarantine records."""
        entries: list[QuarantineEntry] = []
        for path in sorted(self.directory.glob("*.qtn")):
            metadata, _, _ = self._read(path.stem)
            entries.append(QuarantineEntry(**metadata))
        return entries

    def _path(self, item_id: str) -> Path:
        if not item_id or any(ch not in "0123456789abcdef" for ch in item_id.lower()):
            raise ValueError("Invalid quarantine item id")
        path = self.directory / f"{item_id}.qtn"
        if path.parent != self.directory:
            raise ValueError("Invalid quarantine path")
        return path

    def _read(self, item_id: str) -> tuple[dict[str, Any], bytes, bytes]:
        raw = self._path(item_id).read_bytes()
        if len(raw) < len(_MAGIC) + 4 + _NONCE_SIZE + 16 or not raw.startswith(_MAGIC):
            raise ValueError("Invalid quarantine record")
        offset = len(_MAGIC)
        aad_len = int.from_bytes(raw[offset : offset + 4], "big")
        offset += 4
        if aad_len > 1_000_000 or len(raw) < offset + aad_len + _NONCE_SIZE + 16:
            raise ValueError("Invalid quarantine record metadata")
        aad = raw[offset : offset + aad_len]
        offset += aad_len
        nonce = raw[offset : offset + _NONCE_SIZE]
        ciphertext = raw[offset + _NONCE_SIZE :]
        try:
            metadata = json.loads(aad.decode("utf-8"))
            if metadata["item_id"] != item_id:
                raise ValueError("Quarantine metadata id mismatch")
        except (KeyError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("Invalid quarantine metadata") from exc
        return metadata, nonce, ciphertext

    @staticmethod
    def _harden_permissions(path: Path) -> None:
        os.chmod(path, stat.S_IRWXU)

    @staticmethod
    def _atomic_write(path: Path, data: bytes, *, mode: int = 0o600) -> None:
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        tmp = Path(tmp_name)
        try:
            os.fchmod(fd, mode)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
            os.chmod(path, mode)
        finally:
            tmp.unlink(missing_ok=True)
