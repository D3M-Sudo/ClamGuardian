"""Realtime event filtering policy."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from .events import FileEvent, FileEventType


class RealtimePolicy:
    """Evaluate whether filesystem events should trigger automated scanning."""

    DEFAULT_IGNORE_SUFFIXES = (
        ".tmp",
        ".swp",
        ".part",
        ".bak",
        "~",
        ".crdownload",
        ".qtn",
        ".db",
        ".db-wal",
        ".db-shm",
    )

    def __init__(
        self,
        *,
        ignored_extensions: Iterable[str] = (),
        ignored_paths: Iterable[Path] = (),
        scan_created: bool = True,
        scan_modified: bool = True,
    ) -> None:
        self.ignored_suffixes = tuple(
            s.lower() if s.startswith(".") else f".{s.lower()}"
            for s in ignored_extensions
        ) + self.DEFAULT_IGNORE_SUFFIXES
        self.ignored_paths = tuple(Path(p).resolve() for p in ignored_paths)
        self.scan_created = scan_created
        self.scan_modified = scan_modified

    def should_scan(self, event: FileEvent) -> bool:
        """Determine whether *event* should produce a scan task."""
        if event.is_directory:
            return False

        if event.event_type is FileEventType.DELETE:
            return False

        if event.event_type is FileEventType.CREATE and not self.scan_created:
            return False

        if event.event_type is FileEventType.MODIFY and not self.scan_modified:
            return False

        path = event.path
        if any(path.name.endswith(suffix) for suffix in self.ignored_suffixes):
            return False

        try:
            resolved = path.resolve()
            if any(
                resolved == ignored or ignored in resolved.parents
                for ignored in self.ignored_paths
            ):
                return False
        except OSError:
            return False

        return True
