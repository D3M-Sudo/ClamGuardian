"""Bounded asynchronous task runner for AV scans."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path

from .base import BaseAVEngine, ScanResult
from .profiles import ScanProfile


class ScanTaskRunner:
    """Manage a bounded set of cancellable scan tasks.

    Lifecycle guarantee: every task registered in ``_tasks`` is removed when
    it completes, fails or is cancelled (via ``finally`` plus a done
    callback, both idempotent). Cancellation is propagated to the engine,
    which is responsible for terminating its subprocesses before letting
    :class:`asyncio.CancelledError` surface to the caller.
    """

    def __init__(self, engine: BaseAVEngine, max_concurrency: int = 2) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be positive")
        self.engine = engine
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._tasks: set[asyncio.Task[ScanResult]] = set()

    async def submit(
        self,
        target: Path,
        *,
        recursive: bool = True,
        profile: ScanProfile | None = None,
        on_start: Callable[[], None] | None = None,
    ) -> ScanResult:
        """Run one scan while respecting the configured concurrency limit.

        ``profile`` is forwarded to the engine untouched: the runner never
        inspects or translates it (no UI → engine coupling).
        ``on_start`` is invoked exactly once, right after the concurrency
        slot has been acquired — i.e. when the scan actually starts running
        and not while it is still queued.
        """
        async with self._semaphore:
            task = asyncio.current_task()
            if task is not None:
                self._tasks.add(task)
            try:
                if on_start is not None:
                    on_start()
                return await self.engine.scan(Path(target), recursive=recursive, profile=profile)
            finally:
                if task is not None:
                    self._tasks.discard(task)

    def create_task(
        self,
        target: Path,
        *,
        recursive: bool = True,
        profile: ScanProfile | None = None,
        on_start: Callable[[], None] | None = None,
    ) -> asyncio.Task[ScanResult]:
        """Schedule a scan without awaiting it."""
        task = asyncio.create_task(
            self.submit(target, recursive=recursive, profile=profile, on_start=on_start)
        )
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def cancel_all(self) -> None:
        """Cancel all active scans and wait for cancellation to settle."""
        tasks = [task for task in self._tasks if not task.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    @property
    def active_count(self) -> int:
        """Number of scheduled tasks that have not completed."""
        return sum(not task.done() for task in self._tasks)
