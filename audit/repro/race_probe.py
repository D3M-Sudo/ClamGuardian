"""Natural-timing probe: does the duplicate dispatch happen without touching internals?

Run: PYTHONPATH=/workspace /home/node/venvs/audit/bin/python /tmp/audit/race_probe.py
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from clamguardian.core.base import BaseAVEngine, ScanResult
from clamguardian.core.runner import ScanTaskRunner
from clamguardian.realtime import FileEvent, FileEventType, RealtimeScanOrchestrator


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
        await asyncio.sleep(0.3)
        self.active -= 1
        return ScanResult(target=str(target), clean=True)

    async def update_signatures(self) -> str:
        return ""


async def run_case(jitter: float) -> tuple[int, int]:
    base = Path(f"/tmp/audit/race/j{jitter}")
    base.mkdir(parents=True, exist_ok=True)
    f = base / "x.txt"
    f.write_text("x")
    engine = E()
    orch = RealtimeScanOrchestrator(
        ScanTaskRunner(engine, max_concurrency=4), debounce_seconds=0.05, max_queue_depth=100
    )
    await orch.handle_events([FileEvent(path=f, event_type=FileEventType.CREATE)])
    await asyncio.sleep(0.05 + jitter)  # land right on the timer expiry
    await orch.handle_events([FileEvent(path=f, event_type=FileEventType.MODIFY)])
    await asyncio.sleep(1.0)
    await orch.close()
    return len(engine.started), engine.max_active


async def main() -> None:
    for jitter in (0.0, 0.0002, 0.0005, 0.001, 0.002, 0.005):
        n, conc = await run_case(jitter)
        flag = "DUPLICATE" if n > 1 else "ok"
        print(f"jitter=+{jitter * 1000:.1f}ms -> scans={n} max_concurrent={conc}  {flag}")


asyncio.run(main())
