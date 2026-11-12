"""Encrypted quarantine vault using chunked AES-256-GCM."""

from __future__ import annotations

import contextlib
import json
import logging
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
_MAX_CHUNK_SIZE = 8 * 1024 * 1024

logger = logging.getLogger(__name__)


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
        if chunk_size <= 0 or chunk_size > _MAX_CHUNK_SIZE:
            raise ValueError(
                f"Quarantine chunk_size must be between 1 and {_MAX_CHUNK_SIZE} bytes"
            )
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
        """Encrypt a stable regular-file snapshot, then remove that same file."""
        requested = Path(source).expanduser()
        if requested.is_symlink():
            raise ValueError("Refusing to quarantine a symbolic link")
        source = requested.resolve(strict=True)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        with _open_directory_chain(source.parent, create=False) as parent_fd:
            source_fd = os.open(source.name, flags, dir_fd=parent_fd)
            try:
                before = os.fstat(source_fd)
                if not stat.S_ISREG(before.st_mode):
                    raise ValueError("Only regular files can be quarantined")
                size = before.st_size
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
                    with os.fdopen(os.dup(source_fd), "rb") as src:
                        for index in range(chunk_count):
                            chunk = src.read(self.chunk_size)
                            written += len(chunk)
                            if written > self.max_bytes:
                                raise ValueError(
                                    "File grew past the quarantine size limit while being read"
                                )
                            handle.write(
                                self._encrypt_chunk(
                                    nonce, aad, index, index == chunk_count - 1, chunk
                                )
                            )

                after = os.fstat(source_fd)
                if not _same_file_snapshot(before, after) or written != size:
                    destination.unlink(missing_ok=True)
                    raise ValueError("File changed while being quarantined")

                # Move the directory entry to an unpredictable sibling name first.
                # This pins the entry selected by renameat; we then compare that
                # entry with the descriptor whose contents were encrypted.
                staged_name = f".{source.name}.{uuid.uuid4().hex}.clamguardian-pending"
                try:
                    os.rename(
                        source.name,
                        staged_name,
                        src_dir_fd=parent_fd,
                        dst_dir_fd=parent_fd,
                    )
                    staged = os.stat(
                        staged_name, dir_fd=parent_fd, follow_symlinks=False
                    )
                    if not stat.S_ISREG(staged.st_mode) or not _same_file_snapshot(
                        before, staged
                    ):
                        try:
                            _restore_staged_entry(parent_fd, staged_name, source.name)
                        finally:
                            destination.unlink(missing_ok=True)
                        raise ValueError(
                            "Source path changed while being quarantined; "
                            "the replacement was preserved"
                        )
                    try:
                        os.unlink(staged_name, dir_fd=parent_fd)
                    except OSError:
                        _restore_staged_entry(parent_fd, staged_name, source.name)
                        destination.unlink(missing_ok=True)
                        raise
                except OSError:
                    destination.unlink(missing_ok=True)
                    raise

                return self._entry_from_metadata(metadata)
            finally:
                os.close(source_fd)

    def restore(self, item_id: str, destination: Path | None = None) -> Path:
        """Decrypt an item into *destination* and remove its quarantine record."""
        path = self._path(item_id)
        header = self._read_header(item_id)
        target = self._restore_target(header.metadata, destination)
        if not target.name or target.name in {".", ".."}:
            raise ValueError("Invalid or unsafe restore destination")

        # Resolve and pin every parent directory without following symlinks.
        # All subsequent creation and replacement is relative to this descriptor,
        # so swapping a pathname ancestor cannot redirect the restored payload.
        with _open_directory_chain(target.parent, create=True) as parent_fd:
            with _atomic_writer_at(parent_fd, target.name, mode=0o600) as out:
                with path.open("rb") as handle:
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
        entries: list[QuarantineEntry] = []
        for path in sorted(self.directory.glob("*.qtn")):
            try:
                header = self._read_header(path.stem)
                entries.append(self._entry_from_metadata(header.metadata))
            except (OSError, ValueError) as exc:
                logger.warning("Skipping invalid quarantine record %s: %s", path.name, exc)
        return entries


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
        """Parse and bound a record header before reading any ciphertext."""
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
            size = metadata.get("size")
            if (
                not isinstance(size, int)
                or isinstance(size, bool)
                or size < 0
                or size > self.max_bytes
            ):
                raise ValueError("Invalid quarantine record size")

            if magic == _MAGIC_V1:
                nonce = handle.read(_NONCE_SIZE)
                if len(nonce) != _NONCE_SIZE:
                    raise ValueError("Invalid quarantine record")
                data_offset = handle.tell()
                handle.seek(0, os.SEEK_END)
                payload_size = handle.tell() - data_offset
                if payload_size != size + _TAG_SIZE:
                    raise ValueError("Invalid legacy quarantine record size")
                return _RecordHeader(
                    metadata=metadata,
                    aad=aad,
                    nonce=nonce,
                    chunk_size=0,
                    chunk_count=1,
                    data_offset=data_offset,
                    legacy=True,
                )

            raw_geometry = handle.read(8)
            nonce = handle.read(_NONCE_SIZE)
            if len(raw_geometry) != 8 or len(nonce) != _NONCE_SIZE:
                raise ValueError("Invalid quarantine record geometry")
            chunk_size = int.from_bytes(raw_geometry[:4], "big")
            chunk_count = int.from_bytes(raw_geometry[4:], "big")
            if (
                chunk_size <= 0
                or chunk_size > _MAX_CHUNK_SIZE
                or chunk_count < 1
            ):
                raise ValueError("Invalid quarantine record geometry")
            expected_count = max(1, -(-size // chunk_size))
            if chunk_count != expected_count:
                raise ValueError("Invalid quarantine record geometry")
            data_offset = handle.tell()
            handle.seek(0, os.SEEK_END)
            payload_size = handle.tell() - data_offset
            if payload_size != size + chunk_count * _TAG_SIZE:
                raise ValueError("Invalid quarantine record payload size")
            return _RecordHeader(
                metadata=metadata,
                aad=aad,
                nonce=nonce,
                chunk_size=chunk_size,
                chunk_count=chunk_count,
                data_offset=data_offset,
                legacy=False,
            )

    def _restore_target(self, metadata: dict[str, Any], destination: Path | None) -> Path:
        """Resolve a restore path without following any existing symlink."""
        if destination is not None:
            candidate = Path(destination).expanduser()
            if ".." in candidate.parts:
                raise ValueError("Invalid or unsafe restore destination")
            candidate = Path(os.path.abspath(os.fspath(candidate)))
        else:
            raw_original = metadata.get("original_path", "")
            if not isinstance(raw_original, str) or not raw_original:
                raise ValueError("Invalid or unsafe original path in quarantine metadata")
            candidate = Path(raw_original).expanduser()
            if not candidate.is_absolute() or ".." in candidate.parts:
                raise ValueError("Invalid or unsafe original path in quarantine metadata")
            candidate = Path(os.path.abspath(os.fspath(candidate)))

        current = Path(candidate.anchor)
        for component in candidate.parts[1:]:
            current = current / component
            try:
                mode = current.lstat().st_mode
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise ValueError("Cannot safely inspect restore path") from exc
            if stat.S_ISLNK(mode):
                raise ValueError("Refusing to restore through a symbolic link")
        return candidate

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


@contextlib.contextmanager
def _open_directory_chain(path: Path, *, create: bool) -> Iterator[int]:
    """Open an absolute directory path one component at a time, never following symlinks."""
    path = Path(os.path.abspath(os.fspath(path)))
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path.anchor, flags)
    try:
        for component in path.parts[1:]:
            try:
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        yield descriptor
    finally:
        os.close(descriptor)


def _same_file_snapshot(first: os.stat_result, second: os.stat_result) -> bool:
    """Compare inode identity and mutation-sensitive metadata."""
    return (
        first.st_dev,
        first.st_ino,
        first.st_size,
        first.st_mtime_ns,
        first.st_ctime_ns,
    ) == (
        second.st_dev,
        second.st_ino,
        second.st_size,
        second.st_mtime_ns,
        second.st_ctime_ns,
    )


def _restore_staged_entry(parent_fd: int, staged_name: str, original_name: str) -> None:
    """Restore a staged entry without replacing a path installed by another process."""
    try:
        os.link(
            staged_name,
            original_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except FileExistsError:
        # Preserve the staged object under its unpredictable name rather than
        # overwriting a concurrent replacement at the original pathname.
        raise ValueError(
            f"Source replacement detected; original entry preserved as {staged_name}"
        ) from None
    os.unlink(staged_name, dir_fd=parent_fd)


@contextlib.contextmanager
def _atomic_writer_at(
    parent_fd: int, name: str, *, mode: int = 0o600
) -> Iterator[BinaryIO]:
    """Atomically write a file relative to a pinned, already-validated directory."""
    temporary = f".{name}.{secrets.token_hex(16)}.tmp"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(temporary, flags, mode, dir_fd=parent_fd)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            yield handle
            handle.flush()
            os.fsync(handle.fileno())

        try:
            existing = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and (
            stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode)
        ):
            raise ValueError("Refusing to replace a non-regular restore destination")
        os.replace(
            temporary,
            name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
    finally:
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass


def _encode_metadata(metadata: dict[str, Any]) -> bytes:
    return json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()


def _parse_metadata(aad: bytes, item_id: str) -> dict[str, Any]:
    try:
        metadata = json.loads(aad.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("Invalid quarantine metadata") from exc
    if not isinstance(metadata, dict):
        raise ValueError("Invalid quarantine metadata")
    if metadata.get("item_id") != item_id:
        raise ValueError("Quarantine metadata id mismatch")
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
