"""Linux inotify implementation of FileMonitor using inotify_simple."""

from __future__ import annotations

import contextlib
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
    """Linux inotify monitor backed by inotify_simple."""

    def __init__(self) -> None:
        if not INOTIFY_AVAILABLE or inotify_simple is None:
            raise RuntimeError("Linux inotify is not available on this platform")
        self._inotify = inotify_simple.INotify()
        self._wd_map: dict[int, Path] = {}
        self._mask = (
            inotify_simple.flags.CLOSE_WRITE
            | inotify_simple.flags.CREATE
            | inotify_simple.flags.MOVED_TO
            | inotify_simple.flags.DELETE
        )

    def add_watch(self, path: Path) -> int:
        """Add inotify watch on *path*."""
        resolved = Path(path).resolve(strict=True)
        wd = self._inotify.add_watch(str(resolved), self._mask)
        self._wd_map[wd] = resolved
        return wd

    def remove_watch(self, wd: int) -> None:
        """Remove inotify watch descriptor *wd*."""
        if wd in self._wd_map:
            with contextlib.suppress(OSError):
                self._inotify.rm_watch(wd)
            del self._wd_map[wd]

    def read_events(self, timeout: float | None = 0.1) -> Sequence[FileEvent]:
        """Read inotify events and map them into normalized FileEvent objects."""
        if timeout is not None and timeout >= 0:
            r, _, _ = select.select([self._inotify.fd], [], [], timeout)
            if not r:
                return ()

        raw_events = self._inotify.read(timeout=0)
        events: list[FileEvent] = []
        for raw in raw_events:
            parent = self._wd_map.get(raw.wd)
            if parent is None:
                continue
            item_path = parent / raw.name if raw.name else parent
            mask = raw.mask
            flags = inotify_simple.flags

            is_dir = bool(mask & flags.ISDIR)

            if mask & (flags.CREATE | flags.MOVED_TO):
                event_type = FileEventType.CREATE
            elif mask & flags.CLOSE_WRITE:
                event_type = FileEventType.MODIFY
            elif mask & flags.DELETE:
                event_type = FileEventType.DELETE
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
        """Close inotify file descriptor."""
        with contextlib.suppress(OSError):
            self._inotify.close()
        self._wd_map.clear()
