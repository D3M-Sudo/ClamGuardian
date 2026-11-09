"""Descriptor-based, no-symlink file snapshots for realtime scanning."""

from __future__ import annotations

import os
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


class UnsafeRealtimeTarget(OSError):
    """A realtime event cannot be mapped safely to a regular file in a watched root."""


def _open_directory_without_symlinks(path: Path) -> int:
    """Open an absolute directory while refusing symlinks in every component."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    directory_fd = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            next_fd = os.open(component, flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        return directory_fd
    except BaseException:
        os.close(directory_fd)
        raise


def _is_beneath(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


@contextmanager
def secure_file_snapshot(
    target: Path, allowed_roots: tuple[Path, ...]
) -> Iterator[Path]:
    """Yield a private snapshot copied from a no-follow descriptor beneath a watched root.

    Every path component is opened relative to a directory descriptor with
    O_NOFOLLOW. The scanner receives only the private snapshot, never the
    event pathname, so a rename/symlink swap after validation cannot redirect
    the engine to another object. Concurrent in-place mutation during copying
    is detected by comparing descriptor metadata before and after the copy.
    """
    target = Path(os.path.abspath(os.fspath(target)))
    selected_root: Path | None = None
    for root in allowed_roots:
        canonical_root = Path(os.path.abspath(os.fspath(root)))
        if _is_beneath(target, canonical_root):
            selected_root = canonical_root
            break
    if selected_root is None or target == selected_root:
        raise UnsafeRealtimeTarget("event target is outside configured realtime roots")

    relative = target.relative_to(selected_root)
    parts = relative.parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise UnsafeRealtimeTarget("invalid relative event path")

    directory_fd = _open_directory_without_symlinks(selected_root)
    source_fd = -1
    try:
        for component in parts[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd

        source_fd = os.open(
            parts[-1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_fd,
        )
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode):
            raise UnsafeRealtimeTarget("realtime target is not a regular file")

        cache_root = (
            Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
            / "clamguardian"
            / "realtime-snapshots"
        )
        cache_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(cache_root, 0o700)
        with tempfile.TemporaryDirectory(
            prefix="snapshot-", dir=cache_root
        ) as private_dir:
            snapshot = Path(private_dir) / "scan-target"
            snapshot_fd = os.open(
                snapshot,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                0o600,
            )
            try:
                while True:
                    chunk = os.read(source_fd, 1024 * 1024)
                    if not chunk:
                        break
                    view = memoryview(chunk)
                    while view:
                        written = os.write(snapshot_fd, view)
                        view = view[written:]
                os.fsync(snapshot_fd)
            finally:
                os.close(snapshot_fd)

            after = os.fstat(source_fd)
            identity_before = (
                before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns,
            )
            identity_after = (
                after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns,
            )
            if identity_before != identity_after:
                raise UnsafeRealtimeTarget("file changed while creating realtime scan snapshot")
            if snapshot.stat().st_size != before.st_size:
                raise UnsafeRealtimeTarget("incomplete realtime scan snapshot")
            yield snapshot
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        os.close(directory_fd)
