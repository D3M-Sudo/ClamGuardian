"""Natural stress probe: outstanding-work invariant vs max_queue_depth.

Triggers events through the PUBLIC API only (handle_events), randomized timing.
Run: PYTHONPATH=/workspace /home/node/venvs/audit/bin/python /tmp/audit/stress_probe.py
"""

from __future__ import annotations

import asyncio
import random
from pathlib import Path

from clamguardian.core.base import BaseAVEngine, ScanResult
from clamguardian.core.runner import ScanTaskRunner
from clamguardian.realtime import FileEvent, FileEventType, RealtimeScanOrchestrator

DEPTH = 3
CONC = 4


class E(BaseAVEngine):
    name = "e"

    def __init__(self) -> None:
        self.active = 0
        self.max_active = 0
        self.started = 0
        self.per_path: dict[str, int] = {}
        self.duplicates: list[str] = []

    async def scan(self, target: Path, *, recursive: bool = True, profile=None) -> ScanResult:
        key = str(target)
        self.started += 1
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.per_path[key] = self.per_path.get(key, 0) + 1
        if self.per_path[key] > 1:
            self.duplicates.append(f"{Path(key).name}:{self.per_path[key]}")
        await asyncio.sleep(random.uniform(0.005, 0.05))
        self.per_path[key] -= 1
        self.active -= 1
        return ScanResult(target=key, clean=True)

    async def update_signatures(self) -> str:
        return ""


async def main() -> None:
    random.seed(1234)
    base = Path("/tmp/audit/stress")
    base.mkdir(parents=True, exist_ok=True)
    files = []
    for i in range(8):
        p = base / f"f{i}.txt"
        p.write_text("x")
        files.append(p)

    engine = E()
    orch = RealtimeScanOrchestrator(
        ScanTaskRunner(engine, max_concurrency=CONC), debounce_seconds=0.02, max_queue_depth=DEPTH
    )
    peak_accounted = 0
    peak_engine = 0
    running = True

    async def sampler() -> None:
        nonlocal peak_accounted, peak_engine
        while running:
            peak_accounted = max(
                peak_accounted, len(orch._pending_events) + len(orch._active_scans)
            )
            peak_engine = max(peak_engine, engine.active)
            await asyncio.sleep(0.001)

    task = asyncio.create_task(sampler())
    for _ in range(60):
        events = [
            FileEvent(
                path=random.choice(files),
                event_type=random.choice([FileEventType.CREATE, FileEventType.MODIFY]),
            )
            for _ in range(random.randint(1, 4))
        ]
        await orch.handle_events(events)
        await asyncio.sleep(random.uniform(0.001, 0.03))
    running = False
    await task
    await asyncio.sleep(0.3)
    print(
        f"max_queue_depth={DEPTH} max_concurrency={CONC} dropped={orch.dropped_events_count} "
        f"peak(pending+active)={peak_accounted} peak_concurrent_engine_scans={peak_engine} "
        f"scans_started={engine.started} duplicate_dispatches={engine.duplicates}"
    )
    await orch.close()


asyncio.run(main())
