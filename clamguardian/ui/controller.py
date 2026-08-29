"""Reactive GObject controller for AV shield operations."""

from __future__ import annotations

import asyncio
from pathlib import Path

import gi

gi.require_version("GObject", "2.0")  # noqa: E402 - required before gi.repository import
from gi.repository import GObject  # noqa: E402 - gi version must be set first

from ..core.base import ScanResult  # noqa: E402 - follows the gi bootstrap above
from ..core.runner import ScanTaskRunner  # noqa: E402 - follows the gi bootstrap above
from ..engines.clamav import ClamAVEngine  # noqa: E402 - follows the gi bootstrap above


class ShieldTaskController(GObject.Object):
    """Bridge asynchronous scan tasks to native GObject signals."""

    __gsignals__ = {
        "scan-started": (GObject.SignalFlags.RUN_LAST, None, (str,)),
        "scan-finished": (GObject.SignalFlags.RUN_LAST, None, (object,)),
        "threat-detected": (GObject.SignalFlags.RUN_LAST, None, (str, str)),
        "scan-cancelled": (GObject.SignalFlags.RUN_LAST, None, (str,)),
    }

    def __init__(self, engine: ClamAVEngine | None = None, max_concurrency: int = 2) -> None:
        super().__init__()
        self._runner = ScanTaskRunner(engine or ClamAVEngine(), max_concurrency=max_concurrency)

    async def scan(self, target: Path, *, recursive: bool = True) -> ScanResult:
        """Emit lifecycle signals around one asynchronous scan.

        Signal semantics:

        * ``scan-started`` — emitted exactly once, when the scan actually
          starts running (concurrency slot acquired), never while queued.
        * ``threat-detected`` — emitted once per threat found; it does *not*
          imply the scan is over and is emitted before ``scan-finished``.
        * ``scan-finished`` — emitted only when the scan concluded with a
          result (clean, infected, error or timeout).
        * ``scan-cancelled`` — emitted instead of ``scan-finished`` when the
          caller cancels the scan; always followed by re-raising
          :class:`asyncio.CancelledError`.

        Engine exceptions (:class:`~clamguardian.core.errors.EngineError`)
        propagate to the caller untouched: core never converts them into
        signals or generic errors.
        """
        target = Path(target)
        target_label = str(target)
        started_emitted = False

        def _notify_start() -> None:
            nonlocal started_emitted
            if not started_emitted:
                started_emitted = True
                self.emit("scan-started", target_label)

        try:
            result = await self._runner.submit(target, recursive=recursive, on_start=_notify_start)
        except asyncio.CancelledError:
            self.emit("scan-cancelled", target_label)
            raise
        for threat in result.threats:
            self.emit("threat-detected", target_label, threat)
        self.emit("scan-finished", result)
        return result

    def cancel_all(self) -> asyncio.Task[None]:
        """Cancel every currently scheduled scan."""
        return asyncio.create_task(self._runner.cancel_all())
