"""Bounded asynchronous task runner for AV scans."""

from __future__ import annotations

import asyncio
from pathlib import Path

from .base import BaseAVEngine, ScanResult


class ScanTaskRunner:
    """Manage a bounded set of cancellable scan tasks."""

    def __init__(self, engine: BaseAVEngine, max_concurrency: int = 2) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be positive")
        self.engine = engine
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._tasks: set[asyncio.Task[ScanResult]] = set()

    async def submit(self, target: Path, *, recursive: bool = True) -> ScanResult:
        """Run one scan while respecting the configured concurrency limit."""
        async with self._semaphore:
            task = asyncio.current_task()
            if task is not None:
                self._tasks.add(task)
            try:
                return await self.engine.scan(Path(target), recursive=recursive)
            finally:
                if task is not None:
                    self._tasks.discard(task)

    def create_task(self, target: Path, *, recursive: bool = True) -> asyncio.Task[ScanResult]:
        """Schedule a scan without awaiting it."""
        task = asyncio.create_task(self.submit(target, recursive=recursive))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def cancel_all(self) -> None:
        """Cancel all active scans and wait for cancellation to settle."""
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    @property
    def active_count(self) -> int:
        """Number of scheduled tasks that have not completed."""
        return sum(not task.done() for task in self._tasks)
