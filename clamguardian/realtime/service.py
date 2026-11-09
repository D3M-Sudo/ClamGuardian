"""Unified Realtime Monitoring Service connecting InotifyMonitor, Policy, and Orchestrator."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from ..core.base import ScanResult
from ..core.profiles import ScanProfile
from .inotify import InotifyMonitor
from .orchestrator import RealtimeScanOrchestrator
from .policy import RealtimePolicy

if TYPE_CHECKING:
    from ..core.runner import ScanTaskRunner
    from ..history import HistoryStore

logger = logging.getLogger(__name__)


class RealtimeMonitorService:
    """High-level service managing InotifyMonitor, Policy, and RealtimeScanOrchestrator."""

    def __init__(
        self,
        runner: ScanTaskRunner,
        *,
        history_store: HistoryStore | None = None,
        profile: ScanProfile | None = None,
        monitored_paths: Sequence[Path] = (),
        debounce_seconds: float = 0.5,
        max_queue_depth: int = 1000,
        on_scan_complete: Callable[[ScanResult], None] | None = None,
    ) -> None:
        self.runner = runner
        self.history_store = history_store
        self.profile = profile
        self.monitored_paths = [Path(p).resolve() for p in monitored_paths]
        self.debounce_seconds = debounce_seconds
        self.max_queue_depth = max_queue_depth
        self.on_scan_complete = on_scan_complete

        self.policy = RealtimePolicy()
        self.orchestrator = RealtimeScanOrchestrator(
            runner=self.runner,
            policy=self.policy,
            history_store=self.history_store,
            profile=self.profile,
            debounce_seconds=self.debounce_seconds,
            max_queue_depth=self.max_queue_depth,
        )
        self._monitor: InotifyMonitor | None = None
        self._poll_task: asyncio.Task[None] | None = None
        self._running = False

    @property
    def is_running(self) -> bool:
        """Whether monitoring is actively running."""
        return self._running

    @property
    def overflow_count(self) -> int:
        """Total inotify kernel queue overflow events detected."""
        return self._monitor.overflow_count if self._monitor is not None else 0

    @property
    def dropped_events_count(self) -> int:
        """Total events dropped due to backpressure / max queue depth."""
        return self.orchestrator.dropped_events_count

    async def start(self) -> None:
        """Start filesystem event collection and monitoring."""
        if self._running:
            return

        self._monitor = InotifyMonitor()
        for p in self.monitored_paths:
            if p.exists():
                self._monitor.add_watch(p)

        self._running = True
        self._poll_task = asyncio.create_task(self._event_poll_loop())

    async def stop(self) -> None:
        """Stop monitoring and shutdown orchestrator and inotify monitor."""
        self._running = False
        if self._poll_task is not None:
            self._poll_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._poll_task
            self._poll_task = None

        await self.orchestrator.close()

        if self._monitor is not None:
            self._monitor.close()
            self._monitor = None

    async def _event_poll_loop(self) -> None:
        loop = asyncio.get_running_loop()
        while self._running and self._monitor is not None:
            try:
                events = await loop.run_in_executor(None, self._monitor.read_events, 0.2)
                if events:
                    await self.orchestrator.handle_events(
                        events, on_scan_complete=self.on_scan_complete
                    )
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Error in realtime event poll loop: %s", exc)
                await asyncio.sleep(0.5)
