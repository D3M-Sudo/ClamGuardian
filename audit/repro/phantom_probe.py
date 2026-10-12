"""Consequence probe: a stale-path event from a moved-out directory reaches History.

Run: PYTHONPATH=/workspace /home/node/venvs/audit/bin/python /tmp/audit/phantom_probe.py
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

from clamguardian.core.base import BaseAVEngine, ScanResult
from clamguardian.core.runner import ScanTaskRunner
from clamguardian.history import SqliteHistoryStore
from clamguardian.realtime import InotifyMonitor, RealtimeScanOrchestrator


class E(BaseAVEngine):
    name = "e"

    def __init__(self) -> None:
        self.scanned: list[str] = []

    async def scan(self, target: Path, *, recursive: bool = True, profile=None) -> ScanResult:
        self.scanned.append(str(target))
        return ScanResult(target=str(target), clean=True)

    async def update_signatures(self) -> str:
        return ""


async def main() -> None:
    root = Path("/tmp/audit/phantom/root")
    shutil.rmtree(root.parent, ignore_errors=True)
    (root / "sub").mkdir(parents=True)
    out = Path("/tmp/audit/phantom/out")
    out.mkdir(parents=True)

    monitor = InotifyMonitor()
    monitor.add_watch(root)
    shutil.move(str(root / "sub"), str(out / "sub"))
    monitor.read_events(timeout=0.25)
    real_file = out / "sub" / "escaped.txt"
    real_file.write_text("payload")

    events = monitor.read_events(timeout=0.5)
    monitor.close()

    store = SqliteHistoryStore(root.parent / "h.db")
    engine = E()
    orch = RealtimeScanOrchestrator(
        ScanTaskRunner(engine), history_store=store, debounce_seconds=0.0
    )
    tasks = await orch.handle_events(list(events))
    await asyncio.gather(*tasks)
    rows = await store.list_scans()
    await store.close()

    print("events from the monitor:", [str(e.path) for e in events])
    print("real file on disk      :", real_file, "exists:", real_file.exists())
    print("engine actually scanned:", engine.scanned)
    for r in rows:
        print(f"history row -> target={r.target} status={r.status} error={r.error!r}")


asyncio.run(main())
