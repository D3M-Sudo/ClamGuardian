"""Realtime scan orchestrator with event coalescing, trailing-edge debounce, and queue bounds."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable, Sequence
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

logger = logging.getLogger(__name__)


class RealtimeScanOrchestrator:
    """Orchestrate debounced, deduplicated scan tasks from filesystem events.

    Reuses :class:`~clamguardian.core.runner.ScanTaskRunner` for scan execution.
    Mandatory correctness requirements:
    - Push-driven trailing-edge event debouncing via asyncio timers.
    - Strict queue bound: `pending + dispatched/unacquired + active <= max_queue_depth`.
    - Same-path coalescing and deterministic dirty/retrigger handling during active scans.
    - Zero direct SQLite / history entanglement (history passed via application service).
    - Deterministic shutdown cancelling all timers, awaiting active scans, and releasing capacity.
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
        self._dispatched: set[Path] = set()
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

    @property
    def total_outstanding_work(self) -> int:
        """Return total accounted work: pending + dispatched + active."""
        return len(self._pending_events) + len(self._dispatched) + len(self._active_scans)

    async def handle_events(
        self,
        events: Sequence[FileEvent],
        *,
        on_scan_complete: Callable[[ScanResult], None] | None = None,
    ) -> list[asyncio.Task[ScanResult | None]]:
        """Process incoming events, applying debouncing, policy, and strict queue bounds."""
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

                if path in self._active_scans or path in self._dispatched:
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

                if self.total_outstanding_work >= self.max_queue_depth:
                    self._dropped_events_count += 1
                    continue

                self._pending_events[path] = now
                task = self._schedule_timer(loop, path, on_scan_complete)
                if task is not None:
                    returned_tasks.append(task)

            for path in list(self._active_tasks.keys()):
                if self._active_tasks[path] not in returned_tasks:
                    returned_tasks.append(self._active_tasks[path])

        return returned_tasks

    def _schedule_timer(
        self,
        loop: asyncio.AbstractEventLoop,
        path: Path,
        on_scan_complete: Callable[[ScanResult], None] | None,
    ) -> asyncio.Task[ScanResult | None] | None:
        if self.debounce_seconds <= 0:
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
        if self._closed:
            return
        self._pending_events.pop(path, None)
        self._debounce_timers.pop(path, None)
        self._dispatched.add(path)

        task = asyncio.create_task(self._dispatch_scan(path, on_complete))
        self._active_tasks[path] = task

    async def _dispatch_scan(
        self, path: Path, on_complete: Callable[[ScanResult], None] | None = None
    ) -> None:
        async with self._lock:
            self._dispatched.discard(path)
            if self._closed:
                return
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
                    if self.total_outstanding_work < self.max_queue_depth:
                        now = time()
                        self._pending_events[path] = now
                        with contextlib.suppress(RuntimeError):
                            loop = asyncio.get_running_loop()
                            self._schedule_timer(loop, path, on_complete)

    async def close(self) -> None:
        """Shutdown orchestrator deterministically, cancelling timers and waiting for tasks."""
        async with self._lock:
            self._closed = True
            for timer in self._debounce_timers.values():
                timer.cancel()
            self._debounce_timers.clear()
            self._pending_events.clear()
            self._dirty_paths.clear()
            self._dispatched.clear()

        tasks = list(self._active_tasks.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        self._active_tasks.clear()
        self._active_scans.clear()
        await self.runner.cancel_all()
