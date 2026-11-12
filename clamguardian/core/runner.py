"""Thread-safe bounded asynchronous task runner for AV scans."""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Awaitable, Callable
from pathlib import Path

from .base import BaseAVEngine, ScanResult
from .profiles import ScanProfile

logger = logging.getLogger(__name__)


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
        self._result_enricher: (
            Callable[[ScanResult], Awaitable[None]] | None
        ) = None
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

    def set_result_enricher(
        self, enricher: Callable[[ScanResult], Awaitable[None]] | None
    ) -> None:
        """Set the optional best-effort post-scan enrichment callback."""
        self._result_enricher = enricher

    async def _enrich_result(self, result: ScanResult) -> ScanResult:
        enricher = self._result_enricher
        if enricher is None:
            return result
        try:
            await enricher(result)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning(
                "Optional scan-result enrichment failed (%s); preserving AV result",
                type(exc).__name__,
            )
        return result

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
            result = await self.engine.scan(
                Path(target), recursive=recursive, profile=profile
            )
        finally:
            if acquired:
                self._semaphore.release()

        # Remote enrichment must not occupy an AV-engine concurrency slot.
        return await self._enrich_result(result)

    async def submit_fd(
        self,
        fd: int,
        target: Path,
        *,
        profile: ScanProfile | None = None,
    ) -> ScanResult:
        """Scan an already-open descriptor and apply the same enrichment.

        Descriptor support is supplied by the engine implementation. This
        method deliberately has no pathname fallback: unsupported engines
        fail closed rather than scanning a different filesystem object.
        """
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
            result = await scan_fd(fd, target=Path(target), profile=profile)
        finally:
            if acquired:
                self._semaphore.release()
        return await self._enrich_result(result)

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
            if task.done():
                done.set()
                continue
            if loop.is_closed() or not loop.is_running():
                # A stopped loop cannot execute task cancellation or its done
                # callback. Queue cancellation if it may restart, then detach
                # the stale task so shutdown cannot hang or retain it forever.
                if not loop.is_closed():
                    with contextlib.suppress(RuntimeError):
                        loop.call_soon_threadsafe(task.cancel)
                with self._tasks_lock:
                    self._tasks.pop(task, None)
                done.set()
                logger.warning(
                    "Detached scan task whose event loop is no longer running"
                )
                continue
            try:
                loop.call_soon_threadsafe(task.cancel)
            except RuntimeError:
                with self._tasks_lock:
                    self._tasks.pop(task, None)
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
