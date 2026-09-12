"""Linux inotify implementation of FileMonitor using inotify_simple."""

from __future__ import annotations

import contextlib
import os
import select
from collections.abc import Sequence
from pathlib import Path

from .events import FileEvent, FileEventType
from .monitor import FileMonitor

try:
    import inotify_simple

    INOTIFY_AVAILABLE = True
except (ImportError, OSError):  # pragma: no cover
    inotify_simple = None
    INOTIFY_AVAILABLE = False


class InotifyMonitor(FileMonitor):
    """Linux inotify monitor backed by inotify_simple with recursive watch support."""

    def __init__(self) -> None:
        if not INOTIFY_AVAILABLE or inotify_simple is None:
            raise RuntimeError("Linux inotify is not available on this platform")
        self._inotify = inotify_simple.INotify()
        self._wd_map: dict[int, Path] = {}
        self._path_map: dict[Path, int] = {}
        self._root_watches: set[Path] = set()
        self._mask = (
            inotify_simple.flags.CLOSE_WRITE
            | inotify_simple.flags.CREATE
            | inotify_simple.flags.MOVED_TO
            | inotify_simple.flags.DELETE
            | inotify_simple.flags.MOVED_FROM
            | inotify_simple.flags.EXCL_UNLINK
        )

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

        try:
            wd = self._inotify.add_watch(str(dir_path), self._mask)
            self._wd_map[wd] = dir_path
            self._path_map[dir_path] = wd
            return wd
        except OSError:
            # Handle permission error, non-existent path during race, or ENOSPC gracefully
            return -1

    def remove_watch(self, wd: int) -> None:
        """Remove inotify watch descriptor *wd* and any sub-watches if it's a root watch."""
        path = self._wd_map.get(wd)
        if path is None:
            return

        # If removing a root or directory, remove sub-watches under that path
        sub_paths = [p for p in self._path_map if p == path or path in p.parents]
        for p in sub_paths:
            sub_wd = self._path_map.pop(p, None)
            if sub_wd is not None:
                self._wd_map.pop(sub_wd, None)
                with contextlib.suppress(OSError):
                    self._inotify.rm_watch(sub_wd)

        self._root_watches.discard(path)

    def read_events(self, timeout: float | None = 0.1) -> Sequence[FileEvent]:
        """Read inotify events and map them into normalized FileEvent objects."""
        if timeout is not None and timeout >= 0:
            r, _, _ = select.select([self._inotify.fd], [], [], timeout)
            if not r:
                return ()

        raw_events = self._inotify.read(timeout=0)
        events: list[FileEvent] = []
        flags = inotify_simple.flags

        for raw in raw_events:
            parent = self._wd_map.get(raw.wd)
            mask = raw.mask

            if mask & flags.IGNORED:
                # Watch descriptor was removed by kernel or explicit remove
                self._wd_map.pop(raw.wd, None)
                if parent is not None:
                    self._path_map.pop(parent, None)
                continue

            if parent is None:
                continue

            item_path = parent / raw.name if raw.name else parent
            is_dir = bool(mask & flags.ISDIR)

            # Dynamic recursive registration for newly created or moved-in directories
            if (
                is_dir
                and (mask & (flags.CREATE | flags.MOVED_TO))
                and not item_path.is_symlink()
                and item_path.exists()
            ):
                self.add_watch(item_path)

            if mask & (flags.CREATE | flags.MOVED_TO):
                event_type = FileEventType.CREATE
            elif mask & flags.CLOSE_WRITE:
                event_type = FileEventType.MODIFY
            elif mask & flags.DELETE:
                event_type = FileEventType.DELETE
                if is_dir:
                    # Clean up watch mappings if a watched subdirectory was deleted
                    wd = self._path_map.pop(item_path, None)
                    if wd is not None:
                        self._wd_map.pop(wd, None)
            else:
                continue

            events.append(
                FileEvent(
                    path=item_path,
                    event_type=event_type,
                    is_directory=is_dir,
                    cookie=getattr(raw, "cookie", None),
                )
            )
        return tuple(events)

    def close(self) -> None:
        """Close inotify file descriptor and clear state."""
        with contextlib.suppress(OSError):
            self._inotify.close()
        self._wd_map.clear()
        self._path_map.clear()
        self._root_watches.clear()
