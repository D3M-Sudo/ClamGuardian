"""Linux inotify implementation of FileMonitor using libc inotify syscalls."""

from __future__ import annotations

import contextlib
import ctypes
import errno
import logging
import os
import select
import struct
from collections.abc import Sequence
from pathlib import Path

from .events import FileEvent, FileEventType
from .monitor import FileMonitor

logger = logging.getLogger(__name__)

# Load libc for native inotify syscalls
_libc = ctypes.CDLL(None, use_errno=True)

_inotify_init1 = _libc.inotify_init1
_inotify_init1.argtypes = [ctypes.c_int]
_inotify_init1.restype = ctypes.c_int

_inotify_add_watch = _libc.inotify_add_watch
_inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
_inotify_add_watch.restype = ctypes.c_int

_inotify_rm_watch = _libc.inotify_rm_watch
_inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
_inotify_rm_watch.restype = ctypes.c_int

# Constants for inotify flags
IN_ACCESS = 0x00000001
IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_CLOSE_NOWRITE = 0x00000010
IN_OPEN = 0x00000020
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_UNMOUNT = 0x00002000
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_ONLYDIR = 0x01000000
IN_DONT_FOLLOW = 0x02000000
IN_EXCL_UNLINK = 0x04000000
IN_MASK_ADD = 0x20000000
IN_ISDIR = 0x40000000
IN_ONESHOT = 0x80000000

# struct inotify_event format: int wd, uint32_t mask, uint32_t cookie, uint32_t len
_EVENT_FMT = "iIII"
_EVENT_SIZE = struct.calcsize(_EVENT_FMT)


class InotifyMonitor(FileMonitor):
    """Linux inotify monitor using native libc inotify syscalls with recursive watch support."""

    def __init__(self) -> None:
        self.fd = _inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if self.fd < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))

        self._wd_map: dict[int, Path] = {}
        self._path_map: dict[Path, int] = {}
        self._root_watches: set[Path] = set()
        self._overflow_count: int = 0
        self._watch_failures: set[Path] = set()
        self._mask = (
            IN_CLOSE_WRITE
            | IN_CREATE
            | IN_MOVED_TO
            | IN_DELETE
            | IN_MOVED_FROM
            | IN_EXCL_UNLINK
            | IN_DONT_FOLLOW
        )

    @property
    def overflow_count(self) -> int:
        """Return the number of inotify queue overflow events detected."""
        return self._overflow_count

    @property
    def watch_failures(self) -> frozenset[Path]:
        """Paths that could not be registered as inotify watches."""
        return frozenset(self._watch_failures)

    def add_watch(self, path: Path) -> int:
        """Add recursive inotify watch on *path* and all existing subdirectories."""
        resolved = Path(path).resolve(strict=True)
        self._root_watches.add(resolved)
        root_wd = self._add_single_watch(resolved)

        if resolved.is_dir():
            for root, dirs, _files in os.walk(resolved, followlinks=False):
                parent_path = Path(root)
                for dname in dirs:
                    subdir = parent_path / dname
                    if not subdir.is_symlink():
                        self._add_single_watch(subdir)

        return root_wd

    def _add_single_watch(self, dir_path: Path) -> int:
        """Register single directory in inotify if not already watched."""
        if dir_path in self._path_map:
            return self._path_map[dir_path]

        path_bytes = os.fsencode(dir_path)
        wd = _inotify_add_watch(self.fd, path_bytes, self._mask)
        if wd < 0:
            err = ctypes.get_errno()
            if err == errno.ENOSPC:
                logger.error("Inotify watch limit reached (ENOSPC) for %s", dir_path)
            elif err in (errno.ENOENT, errno.EACCES):
                logger.warning("Cannot watch path %s: errno %d", dir_path, err)
            self._watch_failures.add(dir_path)
            return -1

        self._watch_failures.discard(dir_path)
        self._wd_map[wd] = dir_path
        self._path_map[dir_path] = wd
        return wd

    def remove_watch(self, wd: int) -> None:
        """Remove inotify watch descriptor *wd* and any sub-watches if it's a root watch."""
        path = self._wd_map.get(wd)
        if path is None:
            return

        sub_paths = [p for p in self._path_map if p == path or path in p.parents]
        for p in sub_paths:
            sub_wd = self._path_map.pop(p, None)
            if sub_wd is not None:
                self._wd_map.pop(sub_wd, None)
                _inotify_rm_watch(self.fd, sub_wd)

        self._root_watches.discard(path)

    def _cleanup_moved_out_path(self, path: Path) -> None:
        """Unregister watches when a directory is moved out of the watched tree."""
        sub_paths = [p for p in self._path_map if p == path or path in p.parents]
        for p in sub_paths:
            sub_wd = self._path_map.pop(p, None)
            if sub_wd is not None:
                self._wd_map.pop(sub_wd, None)
                _inotify_rm_watch(self.fd, sub_wd)

    def read_events(self, timeout: float | None = 0.1) -> Sequence[FileEvent]:
        """Read inotify events and map them into normalized FileEvent objects."""
        if self.fd < 0:
            return ()

        if timeout is not None and timeout >= 0:
            r, _, _ = select.select([self.fd], [], [], timeout)
            if not r:
                return ()

        try:
            raw_data = os.read(self.fd, 65536)
        except BlockingIOError:
            return ()
        except OSError as err:
            logger.error("Error reading inotify events: %s", err)
            return ()

        events: list[FileEvent] = []
        offset = 0
        total_len = len(raw_data)

        while offset + _EVENT_SIZE <= total_len:
            wd, mask, cookie, name_len = struct.unpack_from(_EVENT_FMT, raw_data, offset)
            offset += _EVENT_SIZE
            raw_name = raw_data[offset : offset + name_len]
            offset += name_len
            name = os.fsdecode(raw_name.split(b"\x00", 1)[0])

            if mask & IN_Q_OVERFLOW:
                self._overflow_count += 1
                logger.error("Inotify queue overflow detected! Events may have been dropped.")
                continue

            parent = self._wd_map.get(wd)

            if mask & IN_IGNORED:
                self._wd_map.pop(wd, None)
                if parent is not None:
                    self._path_map.pop(parent, None)
                continue

            if parent is None:
                continue

            item_path = parent / name if name else parent
            is_dir = bool(mask & IN_ISDIR)

            if mask & IN_MOVED_FROM:
                if is_dir:
                    self._cleanup_moved_out_path(item_path)
                events.append(
                    FileEvent(
                        path=item_path,
                        event_type=FileEventType.DELETE,
                        is_directory=is_dir,
                        cookie=cookie,
                    )
                )
                continue

            if (
                is_dir
                and (mask & (IN_CREATE | IN_MOVED_TO))
                and not item_path.is_symlink()
                and item_path.exists()
            ):
                self.add_watch(item_path)

            if mask & (IN_CREATE | IN_MOVED_TO):
                event_type = FileEventType.CREATE
            elif mask & IN_CLOSE_WRITE:
                event_type = FileEventType.MODIFY
            elif mask & IN_DELETE:
                event_type = FileEventType.DELETE
                if is_dir:
                    del_wd = self._path_map.pop(item_path, None)
                    if del_wd is not None:
                        self._wd_map.pop(del_wd, None)
            else:
                continue

            events.append(
                FileEvent(
                    path=item_path,
                    event_type=event_type,
                    is_directory=is_dir,
                    cookie=cookie,
                )
            )
        return tuple(events)

    def close(self) -> None:
        """Close inotify file descriptor and clear state."""
        if self.fd >= 0:
            with contextlib.suppress(OSError):
                os.close(self.fd)
            self.fd = -1
        self._wd_map.clear()
        self._path_map.clear()
        self._root_watches.clear()
        self._watch_failures.clear()
