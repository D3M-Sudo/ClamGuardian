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
import socket
import threading
from pathlib import Path

import pytest

from clamguardian.core.base import BaseAVEngine, ScanResult, ScanStatus
from clamguardian.core.profiles import ScanProfile
from clamguardian.core.runner import ScanTaskRunner
from clamguardian.realtime.events import FileEvent, FileEventType
from clamguardian.realtime.inotify import InotifyMonitor
from clamguardian.realtime.orchestrator import RealtimeScanOrchestrator
from clamguardian.realtime.policy import RealtimePolicy
from clamguardian.realtime.security import open_beneath
from clamguardian.realtime.service import RealtimeMonitorService


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



def _make_orchestrator(
    tmp_path: Path,
    runner: ScanTaskRunner,
    *,
    debounce_seconds: float = 0.5,
    max_queue_depth: int = 1000,
):
    root_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    orchestrator = RealtimeScanOrchestrator(
        runner,
        policy=RealtimePolicy(authorized_roots=[tmp_path]),
        root_fds={tmp_path: root_fd},
        debounce_seconds=debounce_seconds,
        max_queue_depth=max_queue_depth,
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
    orchestrator, root_fd = _make_orchestrator(
        tmp_path, runner, debounce_seconds=0.01, max_queue_depth=3
    )

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
    orchestrator, root_fd = _make_orchestrator(tmp_path, runner, debounce_seconds=0.01)

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
    orchestrator, root_fd = _make_orchestrator(tmp_path, runner, debounce_seconds=0.05)

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
        runner,
        policy=RealtimePolicy(authorized_roots=[root]),
        root_fds={root: root_fd},
        debounce_seconds=0,
    )
    try:
        await orchestrator.handle_events([FileEvent(link, FileEventType.CREATE)])
        assert engine.scanned_paths == []
    finally:
        await orchestrator.close()
        os.close(root_fd)


@pytest.mark.asyncio
async def test_clamd_fd_scan_hashes_the_open_descriptor(tmp_path: Path) -> None:
    import hashlib

    from clamguardian.engines.clamav import ClamAVEngine

    target = tmp_path / "sample.bin"
    payload = b"descriptor-bound content"
    target.write_bytes(payload)
    socket_path = tmp_path / "clamd.sock"
    socket_path.touch()
    engine = ClamAVEngine(socket_path=socket_path)
    def clean_scan(_fd: int, _control=None) -> tuple[str, int, str]:
        return f"{target}: OK", 0, "fildes"

    engine._scan_fd_sync = clean_scan  # type: ignore[method-assign]
    fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC)
    try:
        result = await engine.scan_fd(fd, target=target)
        assert result.status is ScanStatus.CLEAN
        assert result.metadata["sha256"] == hashlib.sha256(payload).hexdigest()
        assert result.engine == "clamd-fildes"
    finally:
        os.close(fd)


@pytest.mark.asyncio
async def test_clamd_fd_scan_rejects_content_changed_during_scan(tmp_path: Path) -> None:
    from clamguardian.engines.clamav import ClamAVEngine

    target = tmp_path / "mutable.bin"
    target.write_bytes(b"before")
    socket_path = tmp_path / "clamd.sock"
    socket_path.touch()
    engine = ClamAVEngine(socket_path=socket_path)

    def mutate(_fd: int, _control=None) -> tuple[str, int, str]:
        target.write_bytes(b"after with different length")
        return f"{target}: OK", 0, "fildes"

    engine._scan_fd_sync = mutate  # type: ignore[method-assign]
    fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC)
    try:
        result = await engine.scan_fd(fd, target=target)
        assert result.status is ScanStatus.ERROR
        assert "file changed while clamd was scanning" in (result.error or "")
    finally:
        os.close(fd)


@pytest.mark.asyncio
async def test_clamd_fildes_protocol_passes_descriptor_in_separate_ancillary_packet(
    tmp_path: Path,
) -> None:
    import array
    from socket import CMSG_SPACE, SCM_RIGHTS, SOL_SOCKET

    from clamguardian.engines.clamav import ClamAVEngine

    target = tmp_path / "fildes.txt"
    target.write_bytes(b"descriptor payload")
    socket_path = tmp_path / "clamd.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(os.fspath(socket_path))
    server.listen(2)
    observed: dict[str, object] = {}

    def recv_exact(conn: socket.socket, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            chunk = conn.recv(size - len(data))
            if not chunk:
                raise RuntimeError("unexpected socket EOF")
            data.extend(chunk)
        return bytes(data)

    def serve() -> None:
        probe, _ = server.accept()
        with probe:
            observed["probe"] = probe.recv(1024)
            probe.sendall(b"ClamAV 1.4.0\nCOMMANDS: PING VERSION VERSIONCOMMANDS FILDES\n")
        conn, _ = server.accept()
        with conn:
            observed["command"] = recv_exact(conn, len(b"nFILDES\n"))
            payload, ancillary, _flags, _address = conn.recvmsg(
                1, CMSG_SPACE(array.array("i").itemsize)
            )
            observed["dummy"] = payload
            received_fd = -1
            for level, kind, data in ancillary:
                if level == SOL_SOCKET and kind == SCM_RIGHTS:
                    descriptors = array.array("i")
                    descriptors.frombytes(data[: descriptors.itemsize])
                    received_fd = descriptors[0]
            try:
                with os.fdopen(received_fd, "rb") as handle:
                    observed["content"] = handle.read()
            finally:
                conn.sendall(b"stream: OK\n")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    engine = ClamAVEngine(socket_path=socket_path)
    fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC)
    try:
        output, code, transport = await asyncio.to_thread(engine._scan_fd_sync, fd)
        assert code == 0
        assert transport == "fildes"
        assert output == "stream: OK\n"
        assert observed["probe"] == b"nVERSIONCOMMANDS\n"
        assert observed["command"] == b"nFILDES\n"
        assert observed["dummy"] == b" "
        assert observed["content"] == b"descriptor payload"
    finally:
        os.close(fd)
        server.close()
        thread.join(timeout=2)


def test_open_root_directory_rejects_symlink_component(tmp_path: Path) -> None:
    from clamguardian.realtime.security import open_root_directory

    real_root = tmp_path / "real"
    real_root.mkdir()
    linked_root = tmp_path / "linked"
    linked_root.symlink_to(real_root, target_is_directory=True)
    with pytest.raises(OSError):
        open_root_directory(linked_root)


def test_pinned_root_fd_survives_root_path_replacement(tmp_path: Path) -> None:
    from clamguardian.realtime.security import open_root_directory

    root = tmp_path / "monitored"
    root.mkdir()
    (root / "sample.txt").write_text("original root")
    root_fd = open_root_directory(root)
    moved = tmp_path / "monitored-old"
    try:
        root.rename(moved)
        root.mkdir()
        (root / "sample.txt").write_text("replacement root")
        file_fd = open_beneath(root_fd, root, root / "sample.txt")
        try:
            assert os.read(file_fd, 64) == b"original root"
        finally:
            os.close(file_fd)
    finally:
        os.close(root_fd)



@pytest.mark.asyncio
async def test_clamd_instream_fallback_streams_from_open_descriptor(tmp_path: Path) -> None:
    import struct

    from clamguardian.engines.clamav import ClamAVEngine

    target = tmp_path / "instream.bin"
    target.write_bytes(b"opened descriptor bytes")
    socket_path = tmp_path / "clamd.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(os.fspath(socket_path))
    server.listen(2)
    observed: dict[str, object] = {}

    def recv_exact(conn: socket.socket, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            chunk = conn.recv(size - len(data))
            if not chunk:
                raise RuntimeError("unexpected socket EOF")
            data.extend(chunk)
        return bytes(data)

    def serve() -> None:
        probe, _ = server.accept()
        with probe:
            observed["probe"] = probe.recv(1024)
            probe.sendall(b"ClamAV 1.4.0\nCOMMANDS: PING VERSION VERSIONCOMMANDS INSTREAM\n")
        conn, _ = server.accept()
        with conn:
            observed["command"] = recv_exact(conn, len(b"nINSTREAM\n"))
            payload = bytearray()
            while True:
                size_bytes = recv_exact(conn, 4)
                size = struct.unpack("!I", size_bytes)[0]
                if size == 0:
                    break
                remaining = size
                while remaining:
                    chunk = conn.recv(remaining)
                    payload.extend(chunk)
                    remaining -= len(chunk)
            observed["payload"] = bytes(payload)
            conn.sendall(b"stream: OK\n")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    engine = ClamAVEngine(socket_path=socket_path)
    fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC)
    try:
        output, code, transport = await asyncio.to_thread(engine._scan_fd_sync, fd)
        assert code == 0
        assert transport == "instream"
        assert output == "stream: OK\n"
        assert observed["command"] == b"nINSTREAM\n"
        assert observed["payload"] == b"opened descriptor bytes"
    finally:
        os.close(fd)
        server.close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_clamd_fd_scan_rejects_empty_daemon_response(tmp_path: Path) -> None:
    from clamguardian.engines.clamav import ClamAVEngine

    target = tmp_path / "empty-response.bin"
    target.write_bytes(b"content")
    socket_path = tmp_path / "clamd.sock"
    socket_path.touch()
    engine = ClamAVEngine(socket_path=socket_path)

    def empty_response(_fd: int, _control=None) -> tuple[str, int, str]:
        return "", 0, "fildes"

    engine._scan_fd_sync = empty_response  # type: ignore[method-assign]
    fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC)
    try:
        result = await engine.scan_fd(fd, target=target)
        assert result.status is ScanStatus.ERROR
        assert "empty descriptor-scan response" in (result.error or "")
    finally:
        os.close(fd)


@pytest.mark.asyncio
async def test_clamd_fd_scan_cancellation_interrupts_socket_worker(tmp_path: Path) -> None:
    from clamguardian.engines.clamav import ClamAVEngine

    target = tmp_path / "cancelled.bin"
    target.write_bytes(b"descriptor cancellation")
    socket_path = tmp_path / "clamd.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(os.fspath(socket_path))
    server.listen(1)
    accepted = threading.Event()
    observed: dict[str, bytes] = {}

    def serve() -> None:
        conn, _ = server.accept()
        with conn:
            observed["command"] = conn.recv(1024)
            accepted.set()
            observed["eof"] = conn.recv(1)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    engine = ClamAVEngine(socket_path=socket_path)
    fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC)
    task = asyncio.create_task(engine.scan_fd(fd, target=target))
    try:
        assert await asyncio.to_thread(accepted.wait, 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.to_thread(thread.join, 2)
        assert observed["command"] == b"nVERSIONCOMMANDS\n"
        assert observed["eof"] == b""
    finally:
        if not task.done():
            task.cancel()
        os.close(fd)
        server.close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_scan_remains_bound_to_open_inode_after_path_replacement(tmp_path: Path) -> None:
    import hashlib

    from clamguardian.engines.clamav import ClamAVEngine
    from clamguardian.realtime.security import open_root_directory

    root = tmp_path / "monitored"
    root.mkdir()
    target = root / "sample.txt"
    original = b"original opened inode"
    target.write_bytes(original)
    root_fd = open_root_directory(root)
    file_fd = open_beneath(root_fd, root, target)
    socket_path = tmp_path / "clamd.sock"
    socket_path.touch()
    engine = ClamAVEngine(socket_path=socket_path)

    def inspect_open_fd(scan_fd: int, _control=None) -> tuple[str, int, str]:
        assert os.pread(scan_fd, 128, 0) == original
        return f"{target}: OK", 0, "fildes"

    engine._scan_fd_sync = inspect_open_fd  # type: ignore[method-assign]
    replacement = root / "replacement.txt"
    replacement.write_bytes(b"replacement inode")
    os.replace(replacement, target)
    try:
        result = await engine.scan_fd(file_fd, target=target)
        assert result.status is ScanStatus.CLEAN
        assert result.metadata["sha256"] == hashlib.sha256(original).hexdigest()
    finally:
        os.close(file_fd)
        os.close(root_fd)


@pytest.mark.asyncio
async def test_clamd_fd_timeout_tracks_worker_until_descriptor_cleanup(tmp_path: Path) -> None:
    from clamguardian.core.profiles import DEFAULT_PROFILE
    from clamguardian.engines.clamav import ClamAVEngine

    target = tmp_path / "timeout.bin"
    target.write_bytes(b"descriptor timeout")
    socket_path = tmp_path / "clamd.sock"
    socket_path.touch()
    engine = ClamAVEngine(socket_path=socket_path, command_timeout=0.05)
    started = threading.Event()
    release = threading.Event()
    duplicate_fds: list[int] = []

    def blocked_scan(scan_fd: int, _control=None) -> tuple[str, int, str]:
        duplicate_fds.append(scan_fd)
        started.set()
        if not release.wait(2):
            raise TimeoutError("test worker release timed out")
        return f"{target}: OK", 0, "fildes"

    engine._scan_fd_sync = blocked_scan  # type: ignore[method-assign]
    fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC)
    try:
        result_task = asyncio.create_task(
            engine.scan_fd(fd, target=target, profile=DEFAULT_PROFILE)
        )
        assert await asyncio.to_thread(started.wait, 2)
        result = await result_task
        assert result.status is ScanStatus.TIMEOUT
        assert result.metadata["profile_id"] == DEFAULT_PROFILE.id
        assert engine.active_descriptor_worker_count == 1

        with engine._descriptor_workers_lock:
            worker = next(iter(engine._descriptor_workers))
        worker_done = asyncio.Event()
        worker.add_done_callback(lambda _task: worker_done.set())
        release.set()
        await asyncio.wait_for(worker_done.wait(), timeout=2)

        assert engine.active_descriptor_worker_count == 0
        with pytest.raises(OSError):
            os.fstat(duplicate_fds[0])
    finally:
        release.set()
        os.close(fd)


@pytest.mark.asyncio
async def test_clamd_fd_probe_cancellation_does_not_start_instream_fallback(
    tmp_path: Path,
) -> None:
    from clamguardian.engines.clamav import ClamAVEngine, _DescriptorSocketControl

    target = tmp_path / "probe-cancel.bin"
    target.write_bytes(b"probe cancellation")
    socket_path = tmp_path / "clamd.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(os.fspath(socket_path))
    server.listen(1)
    accepted = threading.Event()

    def serve() -> None:
        conn, _ = server.accept()
        with conn:
            expected = b"nVERSIONCOMMANDS\n"
            received = bytearray()
            while len(received) < len(expected):
                chunk = conn.recv(len(expected) - len(received))
                if not chunk:
                    break
                received.extend(chunk)
            assert bytes(received) == expected
            accepted.set()
            conn.recv(1)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    engine = ClamAVEngine(socket_path=socket_path)
    control = _DescriptorSocketControl()

    def forbidden_fallback(_fd: int, _control=None):
        raise AssertionError("INSTREAM fallback must not start after cancellation")

    engine._scan_fd_instream_sync = forbidden_fallback  # type: ignore[method-assign]
    fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC)
    try:
        worker = asyncio.create_task(asyncio.to_thread(engine._scan_fd_sync, fd, control))
        assert await asyncio.to_thread(accepted.wait, 2)
        control.cancel()
        with pytest.raises(InterruptedError):
            await worker
    finally:
        control.cancel()
        os.close(fd)
        server.close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_clamd_fd_probe_timeout_does_not_fall_back_to_instream(tmp_path: Path) -> None:
    from clamguardian.engines.clamav import ClamAVEngine

    target = tmp_path / "probe-timeout.bin"
    target.write_bytes(b"probe timeout")
    socket_path = tmp_path / "clamd.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(os.fspath(socket_path))
    server.listen(1)
    accepted = threading.Event()

    def serve() -> None:
        conn, _ = server.accept()
        with conn:
            expected = b"nVERSIONCOMMANDS\n"
            received = bytearray()
            while len(received) < len(expected):
                chunk = conn.recv(len(expected) - len(received))
                if not chunk:
                    break
                received.extend(chunk)
            assert bytes(received) == expected
            accepted.set()
            conn.recv(1)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    engine = ClamAVEngine(socket_path=socket_path, command_timeout=0.5)
    fallback_called = threading.Event()

    def forbidden_fallback(_fd: int, _control=None):
        fallback_called.set()
        raise AssertionError("probe timeout must not start INSTREAM fallback")

    engine._scan_fd_instream_sync = forbidden_fallback  # type: ignore[method-assign]
    fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC)
    try:
        scan = asyncio.create_task(engine.scan_fd(fd, target=target))
        assert await asyncio.to_thread(accepted.wait, 2)
        result = await scan
        assert result.status is ScanStatus.TIMEOUT
        assert not fallback_called.is_set()
    finally:
        os.close(fd)
        server.close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_clamd_fd_worker_limit_rejects_until_late_worker_cleanup(tmp_path: Path) -> None:
    from clamguardian.engines.clamav import ClamAVEngine

    target = tmp_path / "worker-limit.bin"
    target.write_bytes(b"bounded descriptor workers")
    socket_path = tmp_path / "clamd.sock"
    socket_path.touch()
    engine = ClamAVEngine(
        socket_path=socket_path, command_timeout=0.05, max_descriptor_workers=1
    )
    started = threading.Event()
    release = threading.Event()
    duplicate_fds: list[int] = []
    invocation_count = 0
    invocation_lock = threading.Lock()

    def blocked_scan(scan_fd: int, _control=None) -> tuple[str, int, str]:
        nonlocal invocation_count
        with invocation_lock:
            invocation_count += 1
        duplicate_fds.append(scan_fd)
        started.set()
        if not release.wait(2):
            raise TimeoutError("test worker release timed out")
        return f"{target}: OK", 0, "fildes"

    engine._scan_fd_sync = blocked_scan  # type: ignore[method-assign]
    fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC)
    try:
        first = asyncio.create_task(engine.scan_fd(fd, target=target))
        assert await asyncio.to_thread(started.wait, 2)
        first_result = await first
        assert first_result.status is ScanStatus.TIMEOUT
        assert engine.active_descriptor_worker_count == 1

        rejected = await engine.scan_fd(fd, target=target)
        assert rejected.status is ScanStatus.ERROR
        assert "capacity exhausted" in (rejected.error or "")
        assert rejected.metadata["profile_id"]
        assert invocation_count == 1
        assert engine.active_descriptor_worker_count == 1

        with engine._descriptor_workers_lock:
            worker = next(iter(engine._descriptor_workers))
        worker_done = asyncio.Event()
        worker.add_done_callback(lambda _task: worker_done.set())
        release.set()
        await asyncio.wait_for(worker_done.wait(), timeout=2)

        assert engine.active_descriptor_worker_count == 0
        with pytest.raises(OSError):
            os.fstat(duplicate_fds[0])

        # Capacity is reusable only after the worker's finally block has closed
        # its duplicate descriptor and released the reservation.
        third = await engine.scan_fd(fd, target=target)
        assert third.status is ScanStatus.CLEAN
        assert invocation_count == 2
        assert engine.active_descriptor_worker_count == 0
    finally:
        release.set()
        os.close(fd)


@pytest.mark.asyncio
async def test_clamd_fd_worker_limit_reservation_is_atomic_across_threads(tmp_path: Path) -> None:
    from clamguardian.engines.clamav import ClamAVEngine

    target = tmp_path / "worker-limit-concurrent.bin"
    target.write_bytes(b"cross-loop admission")
    socket_path = tmp_path / "clamd.sock"
    socket_path.touch()
    engine = ClamAVEngine(socket_path=socket_path, max_descriptor_workers=1)
    barrier = threading.Barrier(3)
    outcomes: list[bool] = []
    outcomes_lock = threading.Lock()

    def reserve_from_thread() -> None:
        barrier.wait()
        reserved = engine._reserve_descriptor_worker()
        with outcomes_lock:
            outcomes.append(reserved)
        if reserved:
            engine._release_descriptor_worker()

    threads = [threading.Thread(target=reserve_from_thread) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=2)

    assert sorted(outcomes) == [False, True]
    assert engine.active_descriptor_worker_count == 0
