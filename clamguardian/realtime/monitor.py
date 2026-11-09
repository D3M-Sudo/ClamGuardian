"""Abstract interface for filesystem event monitoring."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from pathlib import Path

from .events import FileEvent


class FileMonitor(ABC):
    """Abstract contract for monitoring filesystem events."""

    @abstractmethod
    def add_watch(self, path: Path) -> int:
        """Register a directory or file path for monitoring and return watch descriptor ID."""
        raise NotImplementedError

    @abstractmethod
    def remove_watch(self, wd: int) -> None:
        """Unregister a watch descriptor ID."""
        raise NotImplementedError

    @abstractmethod
    def read_events(self, timeout: float | None = 0.1) -> Sequence[FileEvent]:
        """Read pending filesystem events."""
        raise NotImplementedError

    @abstractmethod
    def close(self) -> None:
        """Release underlying system resources."""
        raise NotImplementedError
