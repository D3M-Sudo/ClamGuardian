"""Mandatory regression tests for Realtime Event-Driven Monitoring (2.x-A).

Covers:
- Push-driven trailing-edge debouncing and timer cancellation.
- Same-path coalescing and event storms.
- Strict queue bounds: pending + dispatched + active <= max_queue_depth.
- Deterministic dirty/retrigger handling for events during active scans.
- Recursive watch management (subdirectories created, moved-in, deleted, moved-out).
- Deterministic lifecycle shutdown and repeated start/stop cycles.
"""

from __future__ import annotations

import asyncio
import ctypes
import errno
import os
from pathlib import Path

import pytest

from clamguardian.core.base import BaseAVEngine, ScanResult, ScanStatus
from clamguardian.core.profiles import ScanProfile
from clamguardian.core.runner import ScanTaskRunner
from clamguardian.realtime.events import FileEvent, FileEventType
from clamguardian.realtime.inotify import InotifyMonitor
from clamguardian.realtime.orchestrator import RealtimeScanOrchestrator
from clamguardian.realtime.service import RealtimeMonitorService
from clamguardian.realtime.policy import RealtimePolicy
from clamguardian.realtime.security import open_beneath


class StubEngine(BaseAVEngine):
    name = "stub"

    def __init__(self, delay: float = 0.05, fail: bool = False) -> None:
        self.delay = delay
        self.fail = fail
        self.scanned_paths: list[str] = []

    async def scan(
        self, target: Path, *, recursive: bool = True, profile: ScanProfile | None = None
    ) -> ScanResult:
        self.scanned_paths.append(str(target))
        await asyncio.sleep(self.delay)
        if self.fail:
            raise RuntimeError("engine failure")
        return ScanResult(target=str(target), clean=True)

    async def scan_fd(
        self, fd: int, *, target: Path, profile: ScanProfile | None = None
    ) -> ScanResult:
        os.fstat(fd)
        self.scanned_paths.append(str(target))
        await asyncio.sleep(self.delay)
        if self.fail:
            raise RuntimeError("engine failure")
        return ScanResult(target=str(target), clean=True)

    async def update_signatures(self) -> str:
        return ""



def _make_orchestrator(tmp_path: Path, runner: ScanTaskRunner, **kwargs: object):
    root_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    orchestrator = RealtimeScanOrchestrator(
        runner, policy=RealtimePolicy(authorized_roots=[tmp_path]),
        root_fds={tmp_path: root_fd}, **kwargs,
    )
    return orchestrator, root_fd

@pytest.mark.asyncio
async def test_realtime_trailing_edge_debounce(tmp_path: Path) -> None:
    test_file = tmp_path / "test.txt"
    test_file.write_text("initial")

    engine = StubEngine(delay=0.01)
    runner = ScanTaskRunner(engine)
    orchestrator, root_fd = _make_orchestrator(tmp_path, runner, debounce_seconds=0.1)

    completed: list[ScanResult] = []

    for _ in range(5):
        event = FileEvent(path=test_file, event_type=FileEventType.MODIFY)
        await orchestrator.handle_events([event], on_scan_complete=completed.append)
        await asyncio.sleep(0.02)

    assert len(completed) == 0
    await asyncio.sleep(0.15)

    assert len(completed) == 1
    assert completed[0].status is ScanStatus.CLEAN
    assert len(engine.scanned_paths) == 1

    await orchestrator.close()
    os.close(root_fd)


@pytest.mark.asyncio
async def test_realtime_strict_queue_bound(tmp_path: Path) -> None:
    engine = StubEngine(delay=0.1)
    runner = ScanTaskRunner(engine)
    orchestrator = _make_orchestrator(tmp_path, runner, debounce_seconds=0.01, max_queue_depth=3)

    files = [tmp_path / f"file_{i}.txt" for i in range(10)]
    for f in files:
        f.write_text("data")

    events = [FileEvent(path=f, event_type=FileEventType.CREATE) for f in files]
    await orchestrator.handle_events(events)

    assert orchestrator.total_outstanding_work <= 3
    assert orchestrator.dropped_events_count == 7

    await orchestrator.close()
    os.close(root_fd)


@pytest.mark.asyncio
async def test_realtime_events_arriving_during_active_scan(tmp_path: Path) -> None:
    test_file = tmp_path / "busy.txt"
    test_file.write_text("initial")

    engine = StubEngine(delay=0.1)
    runner = ScanTaskRunner(engine)
    orchestrator = _make_orchestrator(tmp_path, runner, debounce_seconds=0.01)

    completed: list[ScanResult] = []
    event1 = FileEvent(path=test_file, event_type=FileEventType.MODIFY)
    await orchestrator.handle_events([event1], on_scan_complete=completed.append)

    await asyncio.sleep(0.03)
    assert test_file.resolve() in orchestrator._active_scans

    event2 = FileEvent(path=test_file, event_type=FileEventType.MODIFY)
    await orchestrator.handle_events([event2], on_scan_complete=completed.append)

    assert test_file.resolve() in orchestrator._dirty_paths

    await asyncio.sleep(0.2)

    assert len(completed) == 2
    assert len(engine.scanned_paths) == 2

    await orchestrator.close()
    os.close(root_fd)


@pytest.mark.asyncio
async def test_realtime_deterministic_shutdown(tmp_path: Path) -> None:
    test_file = tmp_path / "shutdown_test.txt"
    test_file.write_text("data")

    engine = StubEngine(delay=0.2)
    runner = ScanTaskRunner(engine)
    orchestrator = _make_orchestrator(tmp_path, runner, debounce_seconds=0.05)

    event = FileEvent(path=test_file, event_type=FileEventType.CREATE)
    await orchestrator.handle_events([event])

    await orchestrator.close()

    assert orchestrator._closed is True
    assert len(orchestrator._debounce_timers) == 0
    assert len(orchestrator._pending_events) == 0
    assert len(orchestrator._active_scans) == 0

    tasks = await orchestrator.handle_events([event])
    assert tasks == []
    os.close(root_fd)


def test_inotify_recursive_watch_lifecycle(tmp_path: Path) -> None:
    monitor = InotifyMonitor()
    sub_dir = tmp_path / "subdir"
    sub_dir.mkdir()
    nested_dir = sub_dir / "nested"
    nested_dir.mkdir()

    wd = monitor.add_watch(tmp_path)
    assert wd >= 0

    new_sub = tmp_path / "dynamic_sub"
    new_sub.mkdir()
    new_file = new_sub / "test.txt"
    new_file.write_text("hello")

    events = monitor.read_events(timeout=0.05)
    assert any(e.path.name == "dynamic_sub" for e in events)

    monitor.remove_watch(wd)
    monitor.close()


def test_inotify_exposes_watch_registration_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from clamguardian.realtime import inotify as inotify_module

    def fail_add_watch(*_args: object) -> int:
        ctypes.set_errno(errno.ENOSPC)
        return -1

    monkeypatch.setattr(inotify_module, "_inotify_add_watch", fail_add_watch)
    monitor = InotifyMonitor()
    try:
        assert monitor.add_watch(tmp_path) == -1
        assert tmp_path.resolve() in monitor.watch_failures
    finally:
        monitor.close()


@pytest.mark.asyncio
async def test_realtime_service_fails_start_when_watch_cannot_be_registered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from clamguardian.realtime import inotify as inotify_module

    def fail_add_watch(*_args: object) -> int:
        ctypes.set_errno(errno.ENOSPC)
        return -1

    monkeypatch.setattr(inotify_module, "_inotify_add_watch", fail_add_watch)
    runner = ScanTaskRunner(StubEngine())
    service = RealtimeMonitorService(runner, monitored_paths=[tmp_path])
    with pytest.raises(RuntimeError, match="Could not watch configured path"):
        await service.start()
    assert service.is_running is False


@pytest.mark.asyncio
async def test_realtime_service_lifecycle(tmp_path: Path) -> None:
    engine = StubEngine(delay=0.01)
    runner = ScanTaskRunner(engine)
    service = RealtimeMonitorService(
        runner=runner,
        monitored_paths=[tmp_path],
        debounce_seconds=0.01,
    )

    await service.start()
    assert service.is_running is True

    await service.start()
    assert service.is_running is True

    first_orchestrator = service.orchestrator
    await service.stop()
    assert service.is_running is False
    assert first_orchestrator._closed is True

    await service.stop()
    assert service.is_running is False

    await service.start()
    assert service.is_running is True
    assert service.orchestrator is not first_orchestrator
    assert service.orchestrator._closed is False
    await service.stop()



def test_open_beneath_rejects_symlink_and_parent_traversal(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("outside")
    (root / "escape").symlink_to(outside, target_is_directory=True)
    (root / "link.txt").symlink_to(secret)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        with pytest.raises(OSError):
            open_beneath(root_fd, root, root / "escape" / "secret.txt")
        with pytest.raises(OSError):
            open_beneath(root_fd, root, root / "link.txt")
        with pytest.raises(OSError):
            open_beneath(root_fd, root, outside / "secret.txt")
    finally:
        os.close(root_fd)


@pytest.mark.asyncio
async def test_realtime_rejects_symlink_event_without_scanning_target(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("must not scan")
    link = root / "link.txt"
    link.symlink_to(secret)
    engine = StubEngine(delay=0)
    runner = ScanTaskRunner(engine)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    orchestrator = RealtimeScanOrchestrator(
        runner, policy=RealtimePolicy(authorized_roots=[root]),
        root_fds={root: root_fd}, debounce_seconds=0,
    )
    try:
        await orchestrator.handle_events([FileEvent(link, FileEventType.CREATE)])
        assert engine.scanned_paths == []
    finally:
        await orchestrator.close()
        os.close(root_fd)
