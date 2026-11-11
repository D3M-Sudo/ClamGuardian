"""Descriptor-based filesystem access for realtime scans."""

from __future__ import annotations

import os
import stat
from pathlib import Path

_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
_FILE_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


def open_root_directory(path: Path) -> int:
    """Open and pin every component of an absolute root without following symlinks."""
    absolute = Path(os.path.abspath(os.fspath(path)))
    if not absolute.is_absolute():
        raise OSError("configured realtime root must be absolute")
    current_fd = os.open("/", _DIRECTORY_FLAGS)
    try:
        for component in absolute.parts[1:]:
            next_fd = os.open(component, _DIRECTORY_FLAGS, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def open_beneath(root_fd: int, root_path: Path, target_path: Path) -> int:
    """Open a regular file beneath a pinned root, refusing symlinks and traversal."""
    root = Path(os.path.abspath(os.fspath(root_path)))
    target = Path(os.path.abspath(os.fspath(target_path)))
    try:
        relative = target.relative_to(root)
    except ValueError as exc:
        raise OSError("realtime target is outside every authorized root") from exc
    parts = relative.parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise OSError("invalid realtime relative path")
    current_fd = os.dup(root_fd)
    try:
        for component in parts[:-1]:
            next_fd = os.open(component, _DIRECTORY_FLAGS, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        file_fd = os.open(parts[-1], _FILE_FLAGS, dir_fd=current_fd)
        try:
            if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                raise OSError("realtime target is not a regular file")
            return file_fd
        except BaseException:
            os.close(file_fd)
            raise
    finally:
        os.close(current_fd)
