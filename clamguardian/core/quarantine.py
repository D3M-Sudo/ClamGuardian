"""Encrypted quarantine vault using chunked AES-256-GCM."""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import stat
import tempfile
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#: On-disk magic of the chunked (streaming) format written by this class.
_MAGIC_V2 = b"CLAMGUARDIAN-Q2\x00"
#: On-disk magic of the previous single-blob format, still restorable.
_MAGIC_V1 = b"CLAMGUARDIAN-Q1\x00"
_MAGIC_SIZE = 16
_NONCE_SIZE = 12
_KEY_SIZE = 32
_TAG_SIZE = 16
#: Sanity bound for the cleartext metadata block stored in the header.
_MAX_AAD_BYTES = 1_000_000
#: Plaintext processed per AES-GCM operation (1 MiB).
DEFAULT_CHUNK_SIZE = 1024 * 1024
#: Upper bound for a quarantinable file (512 MiB).
DEFAULT_MAX_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class QuarantineEntry:
    """Metadata describing one encrypted quarantine object."""

    item_id: str
    original_name: str
    original_path: str
    created_at: float
    size: int


@dataclass(frozen=True, slots=True)
class _RecordHeader:
    """Parsed record header: everything before the ciphertext."""

    metadata: dict[str, Any]
    aad: bytes
    nonce: bytes
    chunk_size: int
    chunk_count: int
    data_offset: int
    legacy: bool


class QuarantineVault:
    """Store quarantined files as authenticated AES-256-GCM ciphertext.

    The caller owns the 32-byte master key. Keys are deliberately never persisted
    by this class; applications should obtain them from a secure OS keyring or
    secret store. Vault files are created with owner-only permissions.

    Records are encrypted in fixed-size chunks so that neither quarantining nor
    restoring a large file requires holding it in memory: the process footprint
    stays bounded by ``chunk_size`` regardless of the payload size. Each chunk is
    an independent AES-GCM record bound to its index and to the record metadata,
    which makes truncation, reordering and metadata tampering detectable.
    """

    def __init__(
        self,
        directory: Path,
        key: bytes,
        *,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> None:
        if len(key) != _KEY_SIZE:
            raise ValueError("Quarantine key must be exactly 32 bytes (AES-256)")
        if chunk_size <= 0:
            raise ValueError("Quarantine chunk_size must be positive")
        if max_bytes <= 0:
            raise ValueError("Quarantine max_bytes must be positive")
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._harden_permissions(self.directory)
        self.chunk_size = chunk_size
        self.max_bytes = max_bytes
        self._aes = AESGCM(key)

    @staticmethod
    def generate_key() -> bytes:
        """Generate a cryptographically secure AES-256 key."""
        return secrets.token_bytes(_KEY_SIZE)

    def quarantine(self, source: Path) -> QuarantineEntry:
        """Encrypt *source* into the vault and remove the original after success."""
        requested = Path(source)
        if requested.is_symlink():
            # Resolving first would delete the link *target* and leave a
            # dangling link behind: refuse and let the caller decide.
            raise ValueError("Refusing to quarantine a symbolic link")
        source = requested.resolve(strict=True)
        if not source.is_file():
            raise ValueError("Only regular files can be quarantined")
        size = source.stat().st_size
        if size > self.max_bytes:
            raise ValueError(
                f"File is too large to quarantine: {size} bytes exceeds the "
                f"{self.max_bytes} byte limit"
            )

        item_id = uuid.uuid4().hex
        metadata = {
            "item_id": item_id,
            "original_name": source.name,
            "original_path": str(source),
            "created_at": time.time(),
            "size": size,
        }
        aad = _encode_metadata(metadata)
        nonce = secrets.token_bytes(_NONCE_SIZE)
        # At least one chunk is always written, so even an empty file is an
        # authenticated record rather than an unauthenticated empty blob.
        chunk_count = max(1, -(-size // self.chunk_size))
        destination = self.directory / f"{item_id}.qtn"

        written = 0
        with self._atomic_writer(destination) as handle:
            handle.write(_MAGIC_V2)
            handle.write(len(aad).to_bytes(4, "big"))
            handle.write(aad)
            handle.write(self.chunk_size.to_bytes(4, "big"))
            handle.write(chunk_count.to_bytes(4, "big"))
            handle.write(nonce)
            with source.open("rb") as src:
                for index in range(chunk_count):
                    chunk = src.read(self.chunk_size)
                    written += len(chunk)
                    if written > self.max_bytes:
                        raise ValueError(
                            "File grew past the quarantine size limit while being read"
                        )
                    handle.write(
                        self._encrypt_chunk(nonce, aad, index, index == chunk_count - 1, chunk)
                    )

        if written != size:
            # The payload changed between stat() and read(): the metadata would
            # describe bytes that were never encrypted, so nothing is kept.
            destination.unlink(missing_ok=True)
            raise ValueError("File changed size while being quarantined")

        try:
            source.unlink()
        except OSError:
            destination.unlink(missing_ok=True)
            raise
        return self._entry_from_metadata(metadata)

    def restore(self, item_id: str, destination: Path | None = None) -> Path:
        """Decrypt an item into *destination* and remove its quarantine record."""
        path = self._path(item_id)
        header = self._read_header(item_id)
        target = self._restore_target(header.metadata, destination)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

        with self._atomic_writer(target, mode=0o600) as out, path.open("rb") as handle:
            handle.seek(header.data_offset)
            if header.legacy:
                out.write(self._aes.decrypt(header.nonce, handle.read(), header.aad))
            else:
                self._restore_chunks(handle, header, out)

        path.unlink()
        return target

    def _restore_chunks(self, handle: BinaryIO, header: _RecordHeader, out: BinaryIO) -> None:
        """Stream-decrypt a chunked record, verifying its structure as it goes."""
        for index in range(header.chunk_count):
            last = index == header.chunk_count - 1
            wanted = header.chunk_size + _TAG_SIZE if not last else None
            record = handle.read(wanted if wanted is not None else header.chunk_size + _TAG_SIZE)
            if len(record) < _TAG_SIZE or (wanted is not None and len(record) != wanted):
                raise ValueError("Invalid quarantine record: truncated chunk")
            plaintext = self._aes.decrypt(
                _chunk_nonce(header.nonce, index),
                record,
                _chunk_aad(header.aad, index, last),
            )
            if not last and len(plaintext) != header.chunk_size:
                raise ValueError("Invalid quarantine record: short chunk")
            out.write(plaintext)
        if handle.read(1):
            raise ValueError("Invalid quarantine record: trailing data")

    def delete(self, item_id: str) -> None:
        """Permanently remove an encrypted quarantine item."""
        self._path(item_id).unlink(missing_ok=False)

    def list_entries(self) -> list[QuarantineEntry]:
        """Return metadata for all valid quarantine records.

        Only the cleartext header is parsed: listing never decrypts a payload.
        """
        return [
            self._entry_from_metadata(self._read_header(path.stem).metadata)
            for path in sorted(self.directory.glob("*.qtn"))
        ]


    @staticmethod
    def _entry_from_metadata(metadata: dict[str, Any]) -> QuarantineEntry:
        """Build an entry from stored metadata, validating every required field.

        Malformed metadata is reported as ``ValueError`` like every other
        invalid record, instead of leaking ``KeyError``/``TypeError``.
        """
        try:
            return QuarantineEntry(
                item_id=str(metadata["item_id"]),
                original_name=str(metadata["original_name"]),
                original_path=str(metadata["original_path"]),
                created_at=float(metadata["created_at"]),
                size=int(metadata["size"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("Invalid quarantine metadata") from exc

    def _path(self, item_id: str) -> Path:
        if not item_id or any(ch not in "0123456789abcdef" for ch in item_id.lower()):
            raise ValueError("Invalid quarantine item id")
        path = self.directory / f"{item_id}.qtn"
        if path.parent != self.directory:
            raise ValueError("Invalid quarantine path")
        return path

    def _read_header(self, item_id: str) -> _RecordHeader:
        """Parse the cleartext header of a record without reading its payload."""
        with self._path(item_id).open("rb") as handle:
            magic = handle.read(_MAGIC_SIZE)
            if magic not in (_MAGIC_V1, _MAGIC_V2):
                raise ValueError("Invalid quarantine record")
            raw_length = handle.read(4)
            if len(raw_length) != 4:
                raise ValueError("Invalid quarantine record")
            aad_len = int.from_bytes(raw_length, "big")
            if aad_len > _MAX_AAD_BYTES:
                raise ValueError("Invalid quarantine record metadata")
            aad = handle.read(aad_len)
            if len(aad) != aad_len:
                raise ValueError("Invalid quarantine record metadata")
            metadata = _parse_metadata(aad, item_id)

            if magic == _MAGIC_V1:
                nonce = handle.read(_NONCE_SIZE)
                if len(nonce) != _NONCE_SIZE:
                    raise ValueError("Invalid quarantine record")
                return _RecordHeader(
                    metadata=metadata,
                    aad=aad,
                    nonce=nonce,
                    chunk_size=0,
                    chunk_count=1,
                    data_offset=handle.tell(),
                    legacy=True,
                )

            raw_geometry = handle.read(8)
            nonce = handle.read(_NONCE_SIZE)
            if len(raw_geometry) != 8 or len(nonce) != _NONCE_SIZE:
                raise ValueError("Invalid quarantine record")
            chunk_size = int.from_bytes(raw_geometry[:4], "big")
            chunk_count = int.from_bytes(raw_geometry[4:], "big")
            if chunk_size <= 0 or chunk_count < 1:
                raise ValueError("Invalid quarantine record geometry")
            return _RecordHeader(
                metadata=metadata,
                aad=aad,
                nonce=nonce,
                chunk_size=chunk_size,
                chunk_count=chunk_count,
                data_offset=handle.tell(),
                legacy=False,
            )

    def _restore_target(self, metadata: dict[str, Any], destination: Path | None) -> Path:
        """Resolve the restore path, rejecting unsafe stored metadata."""
        if destination is not None:
            return Path(destination).expanduser().resolve()
        raw_original = metadata.get("original_path", "")
        if not isinstance(raw_original, str) or not raw_original:
            raise ValueError("Invalid or unsafe original path in quarantine metadata")
        candidate = Path(raw_original).expanduser()
        # Records written by this vault always store an absolute path; any
        # relative path or ".." component is either corrupt or hostile.
        if not candidate.is_absolute() or any(part == ".." for part in candidate.parts):
            raise ValueError("Invalid or unsafe original path in quarantine metadata")
        return candidate.resolve()

    def _encrypt_chunk(
        self, nonce: bytes, aad: bytes, index: int, last: bool, chunk: bytes
    ) -> bytes:
        return self._aes.encrypt(_chunk_nonce(nonce, index), chunk, _chunk_aad(aad, index, last))

    @staticmethod
    def _harden_permissions(path: Path) -> None:
        if path.is_symlink():
            raise ValueError("Quarantine directory must not be a symbolic link")
        os.chmod(path, stat.S_IRWXU)

    @staticmethod
    @contextlib.contextmanager
    def _atomic_writer(path: Path, *, mode: int = 0o600) -> Iterator[BinaryIO]:
        """Yield a handle to a temp file that is atomically moved into place."""
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        tmp = Path(tmp_name)
        try:
            os.fchmod(fd, mode)
            with os.fdopen(fd, "wb") as handle:
                yield handle
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
            os.chmod(path, mode)
        finally:
            tmp.unlink(missing_ok=True)

    @staticmethod
    def _atomic_write(path: Path, data: bytes, *, mode: int = 0o600) -> None:
        with QuarantineVault._atomic_writer(path, mode=mode) as handle:
            handle.write(data)


def _encode_metadata(metadata: dict[str, Any]) -> bytes:
    return json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()


def _parse_metadata(aad: bytes, item_id: str) -> dict[str, Any]:
    try:
        metadata = json.loads(aad.decode("utf-8"))
        if metadata["item_id"] != item_id:
            raise ValueError("Quarantine metadata id mismatch")
    except (KeyError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("Invalid quarantine metadata") from exc
    if not isinstance(metadata, dict):
        raise ValueError("Invalid quarantine metadata")
    return metadata


def _chunk_nonce(base_nonce: bytes, index: int) -> bytes:
    """Derive a unique 96-bit nonce per chunk from the record's base nonce."""
    return base_nonce[:8] + index.to_bytes(4, "big")


def _chunk_aad(aad: bytes, index: int, last: bool) -> bytes:
    """Bind a chunk to its position and to the record metadata.

    The index makes reordering detectable; the final-chunk flag makes truncation
    at a chunk boundary detectable.
    """
    return aad + index.to_bytes(4, "big") + (b"\x01" if last else b"\x00")
