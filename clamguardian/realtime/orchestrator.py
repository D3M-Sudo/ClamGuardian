"""Realtime scan orchestrator with event coalescing and debouncing."""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from pathlib import Path
from time import time
from typing import TYPE_CHECKING

from ..core.base import ScanResult, ScanStatus
from ..core.profiles import ScanProfile
from .events import FileEvent
from .policy import RealtimePolicy

if TYPE_CHECKING:
    from ..core.runner import ScanTaskRunner
    from ..history import HistoryStore


class RealtimeScanOrchestrator:
    """Orchestrate debounced, deduplicated scan tasks from filesystem events.

    Reuses :class:`~clamguardian.core.runner.ScanTaskRunner` for scan execution.
    Features:
    - Event debouncing and deduplication within a configurable window.
    - Path re-validation before scan execution (handles file disappearance / change).
    - Bounded task queueing.
    - Automatic history recording.
    """

    def __init__(

        self,
        runner: ScanTaskRunner,
        *,
        policy: RealtimePolicy | None = None,
        history_store: HistoryStore | None = None,
        profile: ScanProfile | None = None,
        debounce_seconds: float = 0.5,
        max_queue_depth: int = 1000,
    ) -> None:
        self.runner = runner
        self.policy = policy or RealtimePolicy()
        self.history_store = history_store
        self.profile = profile
        self.debounce_seconds = debounce_seconds
        self.max_queue_depth = max_queue_depth

        self._pending_events: dict[Path, float] = {}
        self._active_scans: set[Path] = set()
        self._lock = asyncio.Lock()

    async def handle_events(
        self,
        events: list[FileEvent] | tuple[FileEvent, ...],
        *,
        on_scan_complete: Callable[[ScanResult], None] | None = None,
    ) -> list[asyncio.Task[ScanResult | None]]:
        """Process incoming events, applying debouncing, policy, and queue bounds."""
        now = time()
        tasks: list[asyncio.Task[ScanResult | None]] = []

        async with self._lock:
            for event in events:
                if not self.policy.should_scan(event):
                    continue

                path = event.path.resolve()
                if (
                    len(self._pending_events) >= self.max_queue_depth
                    and path not in self._pending_events
                ):
                    continue  # queue depth bounded

                self._pending_events[path] = now

            # Schedule debounced scans for paths whose debounce window expired
            ready_paths = [
                p for p, ts in list(self._pending_events.items())
                if (now - ts) >= self.debounce_seconds and p not in self._active_scans
            ]

            for path in ready_paths:
                del self._pending_events[path]
                self._active_scans.add(path)
                task = asyncio.create_task(self._execute_scan(path, on_complete=on_scan_complete))
                tasks.append(task)

        return tasks

    async def _execute_scan(
        self, path: Path, on_complete: Callable[[ScanResult], None] | None = None
    ) -> ScanResult | None:
        try:
            if not path.exists() or not path.is_file():
                # File disappeared or changed type before scan started
                result = ScanResult(
                    target=str(path),
                    clean=False,
                    status=ScanStatus.ERROR,
                    error="File disappeared or changed before scan",
                )
            else:
                result = await self.runner.submit(path, profile=self.profile)

            if self.history_store is not None:
                with contextlib.suppress(Exception):
                    await self.history_store.record_scan(result, profile=self.profile)

            if on_complete is not None:
                on_complete(result)

            return result
        except asyncio.CancelledError:
            return ScanResult.cancelled(str(path))
        finally:
            async with self._lock:
                self._active_scans.discard(path)
