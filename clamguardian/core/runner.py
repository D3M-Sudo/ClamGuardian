"""Thread-safe bounded asynchronous task runner for AV scans."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from pathlib import Path

from .base import BaseAVEngine, ScanResult
from .profiles import ScanProfile


class ScanTaskRunner:
    """Manage cancellable scans submitted from one or more event loops.

    The runner may be shared by the GTK service loop and short-lived UI/CLI
    loops. Therefore its concurrency gate and task registry are deliberately
    thread-safe and do not contain loop-bound asyncio primitives.
    """

    def __init__(self, engine: BaseAVEngine, max_concurrency: int = 2) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be positive")
        self.engine = engine
        self._semaphore = threading.BoundedSemaphore(max_concurrency)
        self._tasks: dict[
            asyncio.Task[ScanResult], tuple[asyncio.AbstractEventLoop, threading.Event]
        ] = {}
        self._tasks_lock = threading.Lock()

    def _track_task(
        self, task: asyncio.Task[ScanResult], loop: asyncio.AbstractEventLoop
    ) -> None:
        with self._tasks_lock:
            if task in self._tasks:
                return
            self._tasks[task] = (loop, threading.Event())
        task.add_done_callback(self._on_task_done)

    def _on_task_done(self, task: asyncio.Task[ScanResult]) -> None:
        with self._tasks_lock:
            tracked = self._tasks.pop(task, None)
        if tracked is not None:
            tracked[1].set()

    async def submit(
        self,
        target: Path,
        *,
        recursive: bool = True,
        profile: ScanProfile | None = None,
        on_start: Callable[[], None] | None = None,
    ) -> ScanResult:
        """Run one scan while respecting the process-wide concurrency limit.

        A non-blocking threading semaphore is polled asynchronously. This
        avoids binding a shared semaphore to whichever event loop submits
        the first scan and remains cancellation-safe while waiting for a slot.
        """
        task = asyncio.current_task()
        if task is not None:
            self._track_task(task, asyncio.get_running_loop())

        acquired = False
        try:
            while not self._semaphore.acquire(blocking=False):
                await asyncio.sleep(0.01)
            acquired = True
            if on_start is not None:
                on_start()
            return await self.engine.scan(
                Path(target), recursive=recursive, profile=profile
            )
        finally:
            if acquired:
                self._semaphore.release()

    def create_task(
        self,
        target: Path,
        *,
        recursive: bool = True,
        profile: ScanProfile | None = None,
        on_start: Callable[[], None] | None = None,
    ) -> asyncio.Task[ScanResult]:
        """Schedule a scan without awaiting it."""
        return asyncio.create_task(
            self.submit(
                target, recursive=recursive, profile=profile, on_start=on_start
            )
        )

    async def submit_fd(
        self,
        fd: int,
        target: Path,
        *,
        profile: ScanProfile | None = None,
    ) -> ScanResult:
        """Scan an already-open descriptor; never fall back to a pathname."""
        scan_fd = getattr(self.engine, "scan_fd", None)
        if not callable(scan_fd):
            raise RuntimeError("engine does not support descriptor-based scanning")
        task = asyncio.current_task()
        if task is not None:
            self._track_task(task, asyncio.get_running_loop())
        acquired = False
        try:
            while not self._semaphore.acquire(blocking=False):
                await asyncio.sleep(0.01)
            acquired = True
            return await scan_fd(fd, target=Path(target), profile=profile)
        finally:
            if acquired:
                self._semaphore.release()

    async def cancel_all(self) -> None:
        """Cancel and await all tracked scans, including scans on other loops."""
        current = asyncio.current_task()
        with self._tasks_lock:
            tracked = [
                (task, loop, done)
                for task, (loop, done) in self._tasks.items()
                if task is not current
            ]

        for task, loop, done in tracked:
            if task.done() or loop.is_closed():
                done.set()
                continue
            try:
                loop.call_soon_threadsafe(task.cancel)
            except RuntimeError:
                done.set()

        if tracked:
            await asyncio.to_thread(
                lambda: [done.wait() for _task, _loop, done in tracked]
            )

    @property
    def active_count(self) -> int:
        """Number of submitted scans that have not completed."""
        with self._tasks_lock:
            return sum(not task.done() for task in self._tasks)
