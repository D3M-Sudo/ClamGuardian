"""Unified Realtime Monitoring Service connecting InotifyMonitor, Policy, and Orchestrator."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from ..core.base import ScanResult
from ..core.profiles import ScanProfile
from .inotify import InotifyMonitor
from .orchestrator import RealtimeScanOrchestrator
from .policy import RealtimePolicy
from .security import open_root_directory

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
        on_status_changed: Callable[[dict[str, object]], None] | None = None,
    ) -> None:
        self.runner = runner
        self.history_store = history_store
        self.profile = profile
        self.monitored_paths = [Path(p).expanduser().absolute() for p in monitored_paths]
        self._root_fds: dict[Path, int] = {}
        self.debounce_seconds = debounce_seconds
        self.max_queue_depth = max_queue_depth
        self.on_scan_complete = on_scan_complete
        self.on_status_changed = on_status_changed
        self._last_overflow_count = 0
        self._last_dropped_events_count = 0
        self._last_watch_failures: frozenset[Path] = frozenset()

        self.policy = RealtimePolicy(authorized_roots=self.monitored_paths)
        self.orchestrator = RealtimeScanOrchestrator(
            runner=self.runner,
            policy=self.policy,
            history_store=self.history_store,
            profile=self.profile,
            debounce_seconds=self.debounce_seconds,
            max_queue_depth=self.max_queue_depth,
            root_fds=self._root_fds,
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
        return (
            self._monitor.overflow_count
            if self._monitor is not None
            else self._last_overflow_count
        )

    @property
    def dropped_events_count(self) -> int:
        """Total events dropped due to backpressure / max queue depth."""
        return (
            self.orchestrator.dropped_events_count
            if self._running
            else self._last_dropped_events_count
        )

    @property
    def watch_failures(self) -> frozenset[Path]:
        """Paths that could not be registered during the active monitor lifecycle."""
        return (
            self._monitor.watch_failures
            if self._monitor is not None
            else self._last_watch_failures
        )

    @property
    def runtime_status(self) -> dict[str, object]:
        """Snapshot runtime health without exposing mutable internal collections."""
        failures = self.watch_failures
        return {
            "running": self.is_running,
            "health": (
                "degraded"
                if failures or self.overflow_count or self.dropped_events_count
                else "healthy" if self.is_running else "stopped"
            ),
            "overflow_count": self.overflow_count,
            "dropped_events_count": self.dropped_events_count,
            "watch_failures": tuple(sorted(str(path) for path in failures)),
        }

    def _notify_status_changed(self) -> None:
        if self.on_status_changed is not None:
            with contextlib.suppress(Exception):
                self.on_status_changed(self.runtime_status)

    async def start(self) -> None:
        """Start filesystem event collection and monitoring."""
        if self._running:
            return

        # stop() closes the previous orchestrator permanently. A new
        # lifecycle must receive a fresh orchestrator and its own queue state.
        self._last_overflow_count = 0
        self._last_dropped_events_count = 0
        self._last_watch_failures = frozenset()
        self._monitor = InotifyMonitor()
        try:
            canonical_roots: list[Path] = []
            for configured_path in self.monitored_paths:
                if configured_path.is_symlink():
                    raise RuntimeError(
                        f"Configured realtime root must not be a symlink: {configured_path}"
                    )
                path = configured_path.resolve(strict=True)
                if not path.is_dir():
                    raise RuntimeError(
                        f"Configured realtime path is not an accessible directory: {path}"
                    )
                root_fd = open_root_directory(path)
                fd_stat = os.fstat(root_fd)
                path_stat = os.stat(path, follow_symlinks=False)
                if (fd_stat.st_dev, fd_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino):
                    os.close(root_fd)
                    raise RuntimeError(f"Configured realtime root changed during startup: {path}")
                self._root_fds[path] = root_fd
                canonical_roots.append(path)

            self.monitored_paths = canonical_roots
            self.policy = RealtimePolicy(authorized_roots=canonical_roots)
            self.orchestrator = RealtimeScanOrchestrator(
                runner=self.runner, policy=self.policy, history_store=self.history_store,
                profile=self.profile, debounce_seconds=self.debounce_seconds,
                max_queue_depth=self.max_queue_depth, root_fds=self._root_fds,
            )
            for path in self.monitored_paths:
                watch = self._monitor.add_watch(path)
                if watch < 0:
                    raise RuntimeError(f"Could not watch configured path: {path}")
                fd_stat = os.fstat(self._root_fds[path])
                path_stat = os.stat(path, follow_symlinks=False)
                if (fd_stat.st_dev, fd_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino):
                    raise RuntimeError(f"Configured realtime root changed while adding watch: {path}")
            if self._monitor.watch_failures:
                failures = ", ".join(str(path) for path in self._monitor.watch_failures)
                raise RuntimeError(f"Realtime monitoring is incomplete; failed watches: {failures}")
        except BaseException:
            self._last_watch_failures = self._monitor.watch_failures
            self._monitor.close()
            self._monitor = None
            for root_fd in self._root_fds.values():
                with contextlib.suppress(OSError):
                    os.close(root_fd)
            self._root_fds.clear()
            self._notify_status_changed()
            raise

        self._running = True
        self._poll_task = asyncio.create_task(self._event_poll_loop())
        self._notify_status_changed()

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
            self._last_overflow_count = self._monitor.overflow_count
            self._last_watch_failures = self._monitor.watch_failures
            self._monitor.close()
            self._monitor = None
        self._last_dropped_events_count = self.orchestrator.dropped_events_count
        for root_fd in self._root_fds.values():
            with contextlib.suppress(OSError):
                os.close(root_fd)
        self._root_fds.clear()
        self._notify_status_changed()

    async def _event_poll_loop(self) -> None:
        loop = asyncio.get_running_loop()
        while self._running and self._monitor is not None:
            try:
                events = await loop.run_in_executor(None, self._monitor.read_events, 0.2)
                if events:
                    await self.orchestrator.handle_events(
                        events, on_scan_complete=self.on_scan_complete
                    )
                # Overflow may arrive without a normal file event; refresh health every read.
                self._notify_status_changed()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Error in realtime event poll loop: %s", exc)
                await asyncio.sleep(0.5)
