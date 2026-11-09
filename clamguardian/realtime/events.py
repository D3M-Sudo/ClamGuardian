"""Normalized event abstraction for filesystem monitoring."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from time import time


class FileEventType(Enum):
    """Normalized filesystem event types."""

    CREATE = "create"
    MODIFY = "modify"
    MOVE = "move"
    DELETE = "delete"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class FileEvent:
    """Normalized, platform-independent filesystem event representation."""

    path: Path
    event_type: FileEventType
    timestamp: float = 0.0
    is_directory: bool = False
    cookie: int | None = None

    def __post_init__(self) -> None:
        if not self.timestamp:
            object.__setattr__(self, "timestamp", time())
        object.__setattr__(self, "path", Path(self.path))
