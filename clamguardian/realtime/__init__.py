"""Event-driven filesystem monitoring package."""

from __future__ import annotations

from .events import FileEvent, FileEventType
from .inotify import INOTIFY_AVAILABLE, InotifyMonitor
from .monitor import FileMonitor
from .orchestrator import RealtimeScanOrchestrator
from .policy import RealtimePolicy

__all__ = [
    "INOTIFY_AVAILABLE",
    "FileEvent",
    "FileEventType",
    "FileMonitor",
    "InotifyMonitor",
    "RealtimePolicy",
    "RealtimeScanOrchestrator",
]
