"""Tests for Phase 12 Event-Driven Monitoring (realtime package)."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from pathlib import Path

import pytest

from clamguardian.core.base import BaseAVEngine, ScanResult, ScanStatus
from clamguardian.core.runner import ScanTaskRunner
from clamguardian.history import SqliteHistoryStore
from clamguardian.realtime import (
    INOTIFY_AVAILABLE,
    FileEvent,
    FileEventType,
    FileMonitor,
    InotifyMonitor,
    RealtimePolicy,
    RealtimeScanOrchestrator,
)


class StubEngine(BaseAVEngine):
    name = "stub"

    def __init__(self, delay: float = 0.01) -> None:
        self.delay = delay
        self.scanned: list[Path] = []

    async def scan(
        self, target: Path, *, recursive: bool = True, profile: object = None
    ) -> ScanResult:
        self.scanned.append(target)
        await asyncio.sleep(self.delay)
        return ScanResult(target=str(target), clean=True)

    async def update_signatures(self) -> str:
        return ""


class FakeMonitor(FileMonitor):
    def __init__(self, events: Sequence[FileEvent] = ()) -> None:
        self._events = list(events)
        self.watches: list[Path] = []

    def add_watch(self, path: Path) -> int:
        self.watches.append(path)
        return len(self.watches)

    def remove_watch(self, wd: int) -> None:
        pass

    def read_events(self, timeout: float | None = 0.1) -> Sequence[FileEvent]:
        res, self._events = self._events, []
        return res

    def close(self) -> None:
        pass


def test_file_event_normalization() -> None:
    event = FileEvent(path=Path("/tmp/sample.txt"), event_type=FileEventType.CREATE)
    assert event.event_type is FileEventType.CREATE
    assert str(event.path) == "/tmp/sample.txt"
    assert event.timestamp > 0


def test_realtime_policy_filtering(tmp_path: Path) -> None:
    policy = RealtimePolicy()

    file_created = FileEvent(path=tmp_path / "valid.doc", event_type=FileEventType.CREATE)
    assert policy.should_scan(file_created) is True

    dir_event = FileEvent(path=tmp_path / "dir", event_type=FileEventType.CREATE, is_directory=True)
    assert policy.should_scan(dir_event) is False

    delete_event = FileEvent(path=tmp_path / "deleted.txt", event_type=FileEventType.DELETE)
    assert policy.should_scan(delete_event) is False

    temp_file = FileEvent(path=tmp_path / "file.tmp", event_type=FileEventType.CREATE)
    assert policy.should_scan(temp_file) is False


@pytest.mark.asyncio
async def test_orchestrator_debouncing_and_deduplication(tmp_path: Path) -> None:
    target = tmp_path / "active_file.txt"
    target.write_text("data")

    engine = StubEngine()
    runner = ScanTaskRunner(engine)
    orchestrator = RealtimeScanOrchestrator(runner, debounce_seconds=0.01)

    events = [
        FileEvent(path=target, event_type=FileEventType.CREATE),
        FileEvent(path=target, event_type=FileEventType.MODIFY),
        FileEvent(path=target, event_type=FileEventType.MODIFY),
    ]

    _tasks = await orchestrator.handle_events(events)
    # Push-driven: sleep past debounce window without invoking handle_events() again
    await asyncio.sleep(0.03)

    assert len(engine.scanned) == 1
    assert engine.scanned[0] == target.resolve()


@pytest.mark.asyncio
async def test_orchestrator_push_debounce_single_event(tmp_path: Path) -> None:
    """P1-REALTIME-DEBOUNCE: Single event triggers scan automatically after debounce window."""
    target = tmp_path / "push_event.txt"
    target.write_text("content")

    engine = StubEngine()
    runner = ScanTaskRunner(engine)
    orchestrator = RealtimeScanOrchestrator(runner, debounce_seconds=0.05)

    events = [FileEvent(path=target, event_type=FileEventType.CREATE)]
    await orchestrator.handle_events(events)

    # Scanned count is initially 0
    assert len(engine.scanned) == 0

    # Wait past debounce window WITHOUT calling handle_events() again
    await asyncio.sleep(0.08)

    assert len(engine.scanned) == 1
    assert engine.scanned[0] == target.resolve()


@pytest.mark.asyncio
async def test_orchestrator_queue_backpressure_bound(tmp_path: Path) -> None:
    """P1-REALTIME-QUEUE-BOUND: Backlog (pending + active) cannot exceed max_queue_depth."""
    engine = StubEngine(delay=0.1)
    runner = ScanTaskRunner(engine, max_concurrency=1)
    orchestrator = RealtimeScanOrchestrator(runner, debounce_seconds=0.01, max_queue_depth=2)

    files = [tmp_path / f"file_{i}.txt" for i in range(5)]
    for f in files:
        f.write_text("data")

    events = [FileEvent(path=f, event_type=FileEventType.CREATE) for f in files]
    await orchestrator.handle_events(events)

    assert orchestrator.dropped_events_count == 3
    await asyncio.sleep(0.2)
    await orchestrator.close()


@pytest.mark.asyncio
async def test_orchestrator_file_disappearance_before_scan(tmp_path: Path) -> None:
    missing_file = tmp_path / "vanished.txt"

    engine = StubEngine()
    runner = ScanTaskRunner(engine)
    orchestrator = RealtimeScanOrchestrator(runner, debounce_seconds=0.0)

    events = [FileEvent(path=missing_file, event_type=FileEventType.CREATE)]
    tasks = await orchestrator.handle_events(events)
    results = await asyncio.gather(*tasks)

    assert len(results) == 1
    assert results[0] is not None
    assert results[0].status is ScanStatus.ERROR
    assert "disappeared or changed" in (results[0].error or "")
    assert len(engine.scanned) == 0


@pytest.mark.asyncio
async def test_orchestrator_history_integration(tmp_path: Path) -> None:
    target = tmp_path / "scanned.txt"
    target.write_text("data")

    store = SqliteHistoryStore(tmp_path / "history.db")
    engine = StubEngine()
    runner = ScanTaskRunner(engine)
    orchestrator = RealtimeScanOrchestrator(runner, history_store=store, debounce_seconds=0.0)

    events = [FileEvent(path=target, event_type=FileEventType.CREATE)]
    tasks = await orchestrator.handle_events(events)
    await asyncio.gather(*tasks)

    records = await store.list_scans()
    assert len(records) == 1
    assert records[0].target == str(target.resolve())


def test_inotify_monitor_instantiation_or_skip() -> None:
    if not INOTIFY_AVAILABLE:
        pytest.skip("Linux inotify is not available in this environment")
    monitor = InotifyMonitor()
    monitor.close()


def test_inotify_monitor_recursive_nested_creation(tmp_path: Path) -> None:
    """P1-REALTIME-RECURSIVE-WATCH: Nested directory tree is monitored recursively."""
    if not INOTIFY_AVAILABLE:
        pytest.skip("Linux inotify is not available in this environment")

    root = tmp_path / "root"
    nested_dir = root / "level1" / "level2"
    nested_dir.mkdir(parents=True)

    monitor = InotifyMonitor()
    monitor.add_watch(root)

    # File created deep in existing nested tree
    target_file = nested_dir / "deep_file.txt"
    target_file.write_text("content")

    events = monitor.read_events(timeout=0.2)
    paths = [e.path for e in events]
    assert target_file.resolve() in [p.resolve() for p in paths]

    # Dynamic creation of new nested directory
    new_dir = root / "new_folder"
    new_dir.mkdir()
    _ = monitor.read_events(timeout=0.2)

    dynamic_file = new_dir / "dynamic.txt"
    dynamic_file.write_text("dynamic")

    events2 = monitor.read_events(timeout=0.2)
    paths2 = [e.path for e in events2]
    assert dynamic_file.resolve() in [p.resolve() for p in paths2]

    monitor.close()
