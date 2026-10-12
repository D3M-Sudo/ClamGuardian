"""Instrumented natural-timing probe with timestamps.

Run: PYTHONPATH=/workspace /home/node/venvs/audit/bin/python /tmp/audit/race_probe2.py
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from time import monotonic

from clamguardian.core.base import BaseAVEngine, ScanResult
from clamguardian.core.runner import ScanTaskRunner
from clamguardian.realtime import FileEvent, FileEventType, RealtimeScanOrchestrator

T0 = monotonic()
LOG: list[str] = []


def log(msg: str) -> None:
    LOG.append(f"t={monotonic() - T0:7.4f} {msg}")


class E(BaseAVEngine):
    name = "e"

    def __init__(self) -> None:
        self.started: list[str] = []
        self.active = 0
        self.max_active = 0

    async def scan(self, target: Path, *, recursive: bool = True, profile=None) -> ScanResult:
        self.started.append(str(target))
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        log(f"engine.scan START #{len(self.started)} (active={self.active})")
        await asyncio.sleep(0.3)
        self.active -= 1
        log(f"engine.scan END   #{len(self.started)} (active={self.active})")
        return ScanResult(target=str(target), clean=True)

    async def update_signatures(self) -> str:
        return ""


async def main() -> None:
    base = Path("/tmp/audit/race2")
    base.mkdir(parents=True, exist_ok=True)
    f = base / "x.txt"
    f.write_text("x")
    engine = E()
    orch = RealtimeScanOrchestrator(
        ScanTaskRunner(engine, max_concurrency=4), debounce_seconds=0.05, max_queue_depth=100
    )
    await orch.handle_events([FileEvent(path=f, event_type=FileEventType.CREATE)])
    log(f"event #1 handled; pending={len(orch._pending_events)} timers={len(orch._debounce_timers)}")
    await asyncio.sleep(0.05)
    log("woke up at debounce expiry")
    await orch.handle_events([FileEvent(path=f, event_type=FileEventType.MODIFY)])
    log(
        f"event #2 handled; pending={len(orch._pending_events)} "
        f"timers={len(orch._debounce_timers)} active_scans={len(orch._active_scans)}"
    )
    await asyncio.sleep(1.0)
    log(f"final: scans={len(engine.started)} max_concurrent={engine.max_active}")
    await orch.close()
    print("\n".join(LOG))


asyncio.run(main())
