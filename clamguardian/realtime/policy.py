"""Realtime event filtering policy."""

from __future__ import annotations

import os
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
        authorized_roots: Iterable[Path] = (),
    ) -> None:
        self.ignored_suffixes = tuple(
            s.lower() if s.startswith(".") else f".{s.lower()}"
            for s in ignored_extensions
        ) + self.DEFAULT_IGNORE_SUFFIXES
        self.ignored_paths = tuple(Path(p).resolve() for p in ignored_paths)
        self.authorized_roots = tuple(Path(os.path.abspath(p)) for p in authorized_roots)
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

        path = Path(os.path.abspath(event.path))
        if not self.authorized_roots or not any(
            path != root and path.is_relative_to(root) for root in self.authorized_roots
        ):
            return False
        if any(path.name.endswith(suffix) for suffix in self.ignored_suffixes):
            return False

        try:
            resolved = path
            if any(
                resolved == ignored or ignored in resolved.parents
                for ignored in self.ignored_paths
            ):
                return False
        except OSError:
            return False

        return True
