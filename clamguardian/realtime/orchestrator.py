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
    - Push-driven trailing-edge event debouncing and deduplication within a configurable window.
    - Path re-validation before scan execution (handles file disappearance / change).
    - Strictly bounded capacity enforcing: pending + active <= max_queue_depth.
    - Active scan dirty marking for re-scanning modified files.
    - Automatic history recording and deterministic shutdown.
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
        self._debounce_timers: dict[Path, asyncio.TimerHandle] = {}
        self._active_scans: set[Path] = set()
        self._active_tasks: dict[Path, asyncio.Task[ScanResult | None]] = {}
        self._dirty_paths: set[Path] = set()
        self._dropped_events_count: int = 0
        self._closed: bool = False
        self._lock = asyncio.Lock()

    @property
    def dropped_events_count(self) -> int:
        """Return the total number of events dropped due to capacity bounds."""
        return self._dropped_events_count

    async def handle_events(
        self,
        events: list[FileEvent] | tuple[FileEvent, ...],
        *,
        on_scan_complete: Callable[[ScanResult], None] | None = None,
    ) -> list[asyncio.Task[ScanResult | None]]:
        """Process incoming events, applying debouncing, policy, and queue bounds.

        In push-driven mode, timers dispatch tasks automatically upon expiration.
        For backwards compatibility and immediate evaluation (e.g. debounce_seconds=0),
        tasks created immediately or pending tasks dispatching now are returned.
        """
        now = time()
        returned_tasks: list[asyncio.Task[ScanResult | None]] = []

        async with self._lock:
            if self._closed:
                return []

            loop = asyncio.get_running_loop()

            for event in events:
                if not self.policy.should_scan(event):
                    continue

                try:
                    path = event.path.resolve()
                except OSError:
                    path = event.path.absolute()

                if path in self._active_scans:
                    self._dirty_paths.add(path)
                    continue

                if path in self._pending_events:
                    self._pending_events[path] = now
                    if path in self._debounce_timers:
                        self._debounce_timers[path].cancel()
                    task = self._schedule_timer(loop, path, on_scan_complete)
                    if task is not None:
                        returned_tasks.append(task)
                    continue

                current_backlog = len(self._pending_events) + len(self._active_scans)
                if current_backlog >= self.max_queue_depth:
                    self._dropped_events_count += 1
                    continue

                self._pending_events[path] = now
                task = self._schedule_timer(loop, path, on_scan_complete)
                if task is not None:
                    returned_tasks.append(task)

            # Gather any active tasks matching pending paths for caller tracking
            for path in list(self._pending_events.keys()):
                if path in self._active_tasks and self._active_tasks[path] not in returned_tasks:
                    returned_tasks.append(self._active_tasks[path])

        return returned_tasks

    def _schedule_timer(
        self,
        loop: asyncio.AbstractEventLoop,
        path: Path,
        on_scan_complete: Callable[[ScanResult], None] | None,
    ) -> asyncio.Task[ScanResult | None] | None:
        if self.debounce_seconds <= 0:
            # Synchronous/Immediate dispatch: create task directly
            self._pending_events.pop(path, None)
            self._active_scans.add(path)
            task = asyncio.create_task(self._execute_scan(path, on_complete=on_scan_complete))
            self._active_tasks[path] = task
            return task
        else:
            self._debounce_timers[path] = loop.call_later(
                self.debounce_seconds, self._on_debounce_expired, path, on_scan_complete
            )
            return None

    def _on_debounce_expired(
        self, path: Path, on_complete: Callable[[ScanResult], None] | None = None
    ) -> None:
        """Callback executed when a debounce timer fires."""
        task = asyncio.create_task(self._dispatch_scan(path, on_complete))
        self._active_tasks[path] = task

    async def _dispatch_scan(
        self, path: Path, on_complete: Callable[[ScanResult], None] | None = None
    ) -> None:
        async with self._lock:
            if self._closed:
                self._pending_events.pop(path, None)
                self._debounce_timers.pop(path, None)
                return

            self._pending_events.pop(path, None)
            self._debounce_timers.pop(path, None)
            self._active_scans.add(path)

        await self._execute_scan(path, on_complete=on_complete)

    async def _execute_scan(
        self, path: Path, on_complete: Callable[[ScanResult], None] | None = None
    ) -> ScanResult | None:
        try:
            if not path.exists() or not path.is_file():
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
                with contextlib.suppress(Exception):
                    on_complete(result)

            return result
        except asyncio.CancelledError:
            return ScanResult.cancelled(str(path))
        finally:
            async with self._lock:
                self._active_scans.discard(path)
                self._active_tasks.pop(path, None)
                if path in self._dirty_paths and not self._closed:
                    self._dirty_paths.remove(path)
                    current_backlog = len(self._pending_events) + len(self._active_scans)
                    if current_backlog < self.max_queue_depth:
                        now = time()
                        self._pending_events[path] = now
                        with contextlib.suppress(RuntimeError):
                            loop = asyncio.get_running_loop()
                            self._schedule_timer(loop, path, on_complete)

    async def close(self) -> None:
        """Shutdown orchestrator, cancelling timers and active scans."""
        async with self._lock:
            self._closed = True
            for timer in self._debounce_timers.values():
                timer.cancel()
            self._debounce_timers.clear()
            self._pending_events.clear()
            self._dirty_paths.clear()

        await self.runner.cancel_all()
