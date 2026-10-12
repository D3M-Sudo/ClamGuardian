"""Read-only empirical probe of clamguardian.realtime invariants.

Run: PYTHONPATH=/workspace /home/node/venvs/audit/bin/python /tmp/audit/rt_probe.py
"""

from __future__ import annotations

import asyncio
import sys
import traceback
from pathlib import Path

from clamguardian.core.base import BaseAVEngine, ScanResult
from clamguardian.core.runner import ScanTaskRunner
from clamguardian.realtime import FileEvent, FileEventType, RealtimeScanOrchestrator

RESULTS: list[tuple[str, str, str]] = []


def record(name: str, verdict: str, detail: str) -> None:
    RESULTS.append((name, verdict, detail))
    print(f"[{verdict}] {name}\n    {detail}")


class CountingEngine(BaseAVEngine):
    name = "counting"

    def __init__(self, delay: float = 0.05) -> None:
        self.delay = delay
        self.active = 0
        self.max_active = 0
        self.per_path_active: dict[str, int] = {}
        self.max_per_path = 0
        self.started: list[str] = []
        self.finished: list[str] = []

    async def scan(self, target: Path, *, recursive: bool = True, profile=None) -> ScanResult:
        key = str(target)
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.per_path_active[key] = self.per_path_active.get(key, 0) + 1
        self.max_per_path = max(self.max_per_path, self.per_path_active[key])
        self.started.append(key)
        try:
            await asyncio.sleep(self.delay)
        finally:
            self.per_path_active[key] -= 1
            self.active -= 1
            self.finished.append(key)
        return ScanResult(target=key, clean=True)

    async def update_signatures(self) -> str:
        return ""


def make(tmp: Path, *, delay: float = 0.05, debounce: float = 0.05, depth: int = 10, conc: int = 2):
    engine = CountingEngine(delay=delay)
    runner = ScanTaskRunner(engine, max_concurrency=conc)
    orch = RealtimeScanOrchestrator(runner, debounce_seconds=debounce, max_queue_depth=depth)
    return engine, runner, orch


def ev(p: Path, t: FileEventType = FileEventType.CREATE) -> FileEvent:
    return FileEvent(path=p, event_type=t)


async def scenario_a_single_event_debounce(tmp: Path) -> None:
    """P1-REALTIME-DEBOUNCE: one single event must trigger a scan after the window."""
    f = tmp / "a.txt"
    f.write_text("x")
    engine, _runner, orch = make(tmp, delay=0.01, debounce=0.05)
    await orch.handle_events([ev(f)])
    await asyncio.sleep(0.25)
    await orch.close()
    if len(engine.started) == 1:
        record("A single-event debounce", "PASS", f"1 scan after quiet window: {engine.started}")
    else:
        record(
            "A single-event debounce",
            "FAIL",
            f"expected 1 scan from a single event, got {len(engine.started)}: {engine.started}",
        )


async def scenario_b_duplicate_timer(tmp: Path) -> None:
    """Duplicate concurrent scans of the SAME path (timer popped without cancel)."""
    f = tmp / "b.txt"
    f.write_text("x")
    engine, _runner, orch = make(tmp, delay=0.30, debounce=0.05)
    path = f.resolve()

    await orch.handle_events([ev(f)])  # arms timer H1 (t0+0.05)
    orch._on_debounce_expired(path, None)  # H1 fires -> dispatch task T1 queued
    await orch.handle_events([ev(f, FileEventType.MODIFY)])  # same loop turn, before T1 runs

    timers_after = [str(p) for p in orch._debounce_timers]
    await asyncio.sleep(0.6)
    await orch.close()

    detail = (
        f"scans started for the same path={engine.started.count(str(path))} "
        f"(engine.started={engine.started}), max concurrent scans of one path="
        f"{engine.max_per_path}, timers still armed when the dispatch task started={timers_after}"
    )
    verdict = "FAIL" if engine.started.count(str(path)) > 1 else "PASS"
    record("B duplicate concurrent scan of one path", verdict, detail)


async def scenario_c_queue_bound(tmp: Path) -> None:
    """P1-REALTIME-QUEUE-BOUND: pending + active must stay <= max_queue_depth."""
    files = []
    for i in range(6):
        p = tmp / f"c{i}.txt"
        p.write_text("x")
        files.append(p)
    engine, _runner, orch = make(tmp, delay=0.30, debounce=0.05, depth=2, conc=4)

    samples: list[int] = []
    running = True

    async def sampler() -> None:
        while running:
            samples.append(len(orch._pending_events) + len(orch._active_scans))
            await asyncio.sleep(0.002)

    task = asyncio.create_task(sampler())
    await orch.handle_events([ev(p) for p in files])
    for p in files[:2]:
        orch._on_debounce_expired(p.resolve(), None)
    await orch.handle_events([ev(p, FileEventType.MODIFY) for p in files[:2]])
    await asyncio.sleep(1.5)
    running = False
    await task
    await orch.close()

    detail = (
        f"max_queue_depth=2, dropped={orch.dropped_events_count}, "
        f"max(pending+active)={max(samples)}, max concurrent engine scans={engine.max_active}, "
        f"scans started={len(engine.started)}"
    )
    verdict = "FAIL" if engine.max_active > 2 or max(samples) > 2 else "PASS"
    record("C queue bound under load", verdict, detail)


async def scenario_d_shutdown(tmp: Path) -> None:
    """Shutdown: no scan may start after close(), no task/state may leak."""
    files = []
    for i in range(3):
        p = tmp / f"d{i}.txt"
        p.write_text("x")
        files.append(p)
    engine, runner, orch = make(tmp, delay=0.20, debounce=0.0, conc=1)

    await orch.handle_events([ev(p) for p in files])
    await asyncio.sleep(0.05)  # first scan running, others queued on the semaphore
    await orch.close()
    started_at_close = len(engine.started)
    await asyncio.sleep(0.9)
    started_after_close = len(engine.started) - started_at_close

    engine2, _r2, orch2 = make(tmp, delay=0.01, debounce=0.05)
    p2 = (tmp / "d0.txt").resolve()
    orch2._on_debounce_expired(p2, None)
    await orch2.close()
    await asyncio.sleep(0.2)
    leaked = len(orch2._active_tasks)

    detail = (
        f"scans started AFTER close()={started_after_close} "
        f"(engine.started={engine.started}); runner.active_count={runner.active_count}; "
        f"_active_tasks leaked after an aborted dispatch={leaked}"
    )
    verdict = "FAIL" if (started_after_close or leaked) else "PASS"
    record("D shutdown lifecycle", verdict, detail)


async def scenario_e_cancellation(tmp: Path) -> None:
    """Cancellation must propagate (no swallow) and must stop the engine call."""
    f = tmp / "e.txt"
    f.write_text("x")
    engine, _runner, orch = make(tmp, delay=0.30, debounce=0.0, conc=1)
    tasks = await orch.handle_events([ev(f)])
    await asyncio.sleep(0.05)
    await orch.close()
    await asyncio.sleep(0.05)
    states = [(t.done(), t.cancelled()) for t in tasks]
    detail = (
        f"dispatch task states (done, cancelled)={states}; "
        f"engine finished={engine.finished}, active={engine.active}"
    )
    swallowed = bool(states) and all(done and not cancelled for done, cancelled in states)
    record("E cancellation propagation", "FAIL" if swallowed else "PASS", detail)


async def scenario_f_dirty_rescan(tmp: Path) -> None:
    """A file modified while its scan is running must be re-scanned exactly once."""
    f = tmp / "f.txt"
    f.write_text("x")
    engine, _runner, orch = make(tmp, delay=0.20, debounce=0.02, conc=2)
    await orch.handle_events([ev(f)])
    await asyncio.sleep(0.08)  # scan in flight
    await orch.handle_events([ev(f, FileEventType.MODIFY)])
    await asyncio.sleep(0.8)
    await orch.close()
    n = engine.started.count(str(f.resolve()))
    detail = f"scans of the modified path={n}; residual _dirty_paths={orch._dirty_paths}"
    record("F dirty re-scan of modified file", "PASS" if n == 2 else "FAIL", detail)


async def scenario_g_history_contract(tmp: Path) -> None:
    """History recording must be best-effort and must cover failed scans."""
    from clamguardian.history import SqliteHistoryStore

    f = tmp / "g.txt"
    f.write_text("x")
    store = SqliteHistoryStore(tmp / "h.db")
    engine = CountingEngine(delay=0.01)
    runner = ScanTaskRunner(engine)
    orch = RealtimeScanOrchestrator(runner, history_store=store, debounce_seconds=0.0)
    await orch.handle_events([ev(f)])
    await asyncio.sleep(0.25)

    missing = tmp / "vanished.txt"
    await orch.handle_events([ev(missing)])
    await asyncio.sleep(0.25)
    rows = await store.list_scans()
    statuses = sorted(r.status for r in rows)

    class Boom:
        async def record_scan(self, result, profile=None):
            raise RuntimeError("disk full")

    orch2 = RealtimeScanOrchestrator(
        ScanTaskRunner(CountingEngine(delay=0.01)), history_store=Boom(), debounce_seconds=0.0
    )
    t = await orch2.handle_events([ev(f)])
    res = await asyncio.gather(*t, return_exceptions=True)
    detail = (
        f"history statuses for clean+vanished scan={statuses}; "
        f"failing store -> result={res!r}"
    )
    ok = "error" in statuses and not isinstance(res[0], BaseException)
    record("G history best-effort + failure rows", "PASS" if ok else "FAIL", detail)
    await store.close()


async def main() -> None:
    base = Path("/tmp/audit/rt")
    base.mkdir(parents=True, exist_ok=True)
    scenarios = [
        scenario_a_single_event_debounce,
        scenario_b_duplicate_timer,
        scenario_c_queue_bound,
        scenario_d_shutdown,
        scenario_e_cancellation,
        scenario_f_dirty_rescan,
        scenario_g_history_contract,
    ]
    for i, scenario in enumerate(scenarios):
        tmp = base / f"s{i}"
        tmp.mkdir(parents=True, exist_ok=True)
        try:
            await scenario(tmp)
        except Exception:
            record(scenario.__name__, "ERROR", traceback.format_exc().splitlines()[-1])
    print("\n==== SUMMARY ====")
    for name, verdict, _ in RESULTS:
        print(f"{verdict:5} {name}")
    fails = [n for n, v, _ in RESULTS if v != "PASS"]
    print(f"\nnon-PASS: {len(fails)} -> {fails}")


if __name__ == "__main__":
    asyncio.run(main())
    sys.exit(0)

