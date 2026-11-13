"""Diagnostic characterization tests for subprocess and scan orchestration.

These tests intentionally describe current behavior; they do not change or
prescribe production behavior. They use synthetic child processes and mocked
clamd endpoints, so no ClamAV installation is required.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from clamguardian.core.base import BaseAVEngine, ScanResult
from clamguardian.core.runner import ScanTaskRunner
from clamguardian.core.scheduler import ScheduledScanManager
from clamguardian.core.settings import AppSettings, SettingsStore
from clamguardian.engines.clamav import ClamAVEngine


@pytest.mark.asyncio
async def test_freshclam_progress_resets_inactivity_timeout(tmp_path: Path) -> None:
    """Continuous progress prevents inactivity timeout but not the hard deadline."""
    executable = tmp_path / "freshclam-progress"
    executable.write_text(
        "#!/usr/bin/env python3\n"
        "import time\n"
        "for _ in range(12):\n"
        "    print('Downloading database: progress', flush=True)\n"
        "    time.sleep(0.1)\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    engine = ClamAVEngine(
        freshclam_binary=str(executable),
        command_inactivity_timeout=0.5,
        command_maximum_timeout=2.0,
    )

    output, exit_code = await engine._run_command([str(executable)])

    assert exit_code == 0
    assert "Downloading database" in output


@pytest.mark.asyncio
async def test_freshclam_progress_does_not_extend_maximum_execution_timeout(
    tmp_path: Path,
) -> None:
    """Continuous output cannot keep FreshClam alive beyond the hard deadline."""
    executable = tmp_path / "freshclam-progress"
    executable.write_text(
        "#!/usr/bin/env python3\n"
        "import time\n"
        "while True:\n"
        "    print('Downloading database: progress', flush=True)\n"
        "    time.sleep(0.02)\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    engine = ClamAVEngine(
        freshclam_binary=str(executable),
        command_inactivity_timeout=1.0,
        command_maximum_timeout=0.25,
    )

    started = time.monotonic()
    with pytest.raises(TimeoutError):
        await engine._run_command([str(executable)])
    elapsed = time.monotonic() - started

    assert 0.20 <= elapsed < 3.0


@pytest.mark.asyncio
async def test_scan_timeout_preserves_partial_detections(tmp_path: Path) -> None:
    """A timeout remains TIMEOUT while detections emitted before it are retained."""
    target = tmp_path / "sample.bin"
    target.write_bytes(b"sample")
    detection = f"{target}: Eicar-Test-Signature FOUND"
    script = (
        "import time; "
        f"print({detection!r}, flush=True); "
        "time.sleep(5)"
    )
    engine = ClamAVEngine(
        socket_path=tmp_path / "missing.sock",
        command_inactivity_timeout=0.2,
        command_maximum_timeout=1.0,
    )

    async def timed_cli(_target: Path, *, profile):
        return await engine._run_command([sys.executable, "-c", script])

    engine._run_cli_scan = timed_cli
    result = await engine.scan(target)

    assert result.status.name == "TIMEOUT"
    assert result.clean is False
    assert detection in result.threats
    assert result.metadata["partial_output"].find(detection) >= 0


@pytest.mark.asyncio
async def test_cli_command_bounds_output_but_preserves_late_detections() -> None:
    """Output retention is bounded while detections after the cap remain visible."""
    limit = 1024
    detection = "/tmp/infected.bin: Eicar-Test-Signature FOUND"
    script = (
        "import sys; "
        "sys.stdout.write('O' * 262144 + chr(10)); "
        "sys.stdout.flush(); "
        f"sys.stderr.write('E' * 262144 + chr(10) + {detection!r} + chr(10)); "
        "sys.stderr.flush()"
    )
    engine = ClamAVEngine(command_max_output_bytes=limit)

    output, exit_code = await engine._run_command([sys.executable, "-S", "-c", script])

    assert exit_code == 0
    assert len(output.encode("utf-8")) <= limit + len(detection.encode("utf-8")) + 128
    assert detection in output
    assert "OUTPUT_TRUNCATED" in output
    result = engine._result(
        Path("/tmp/infected.bin"),
        datetime.now(UTC),
        output,
        exit_code,
        "clamscan",
    )
    assert result.metadata["output_truncated"] == "true"


@pytest.mark.asyncio
async def test_clamd_connection_refused_falls_back_to_clamscan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """An unavailable clamd socket may safely select the CLI backend."""
    target = tmp_path / "sample.bin"
    target.write_bytes(b"sample")
    socket_path = tmp_path / "clamd.ctl"
    socket_path.touch()
    engine = ClamAVEngine(socket_path=socket_path)
    cli_calls = 0

    async def refused_socket(_target: Path, _profile, response_buffer=None):
        raise ConnectionRefusedError("synthetic clamd connection refusal")

    async def fake_cli(_target: Path, *, profile):
        nonlocal cli_calls
        cli_calls += 1
        return f"{target}: OK\n", 0

    monkeypatch.setattr(engine, "_scan_socket", refused_socket)
    monkeypatch.setattr(engine, "_run_cli_scan", fake_cli)

    result = await engine.scan(target)

    assert cli_calls == 1
    assert result.engine == "clamscan"
    assert result.status.name == "CLEAN"


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["timeout", "protocol_error", "other_os_error"])
async def test_clamd_timeout_and_invalid_responses_do_not_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure: str,
) -> None:
    """An incomplete or invalid clamd attempt must not launch a second scan."""
    target = tmp_path / "sample.bin"
    target.write_bytes(b"sample")
    socket_path = tmp_path / "clamd.ctl"
    socket_path.touch()
    engine = ClamAVEngine(socket_path=socket_path, command_timeout=0.05)
    cli_calls = 0

    async def failing_socket(_target: Path, _profile, response_buffer=None):
        if failure == "timeout":
            await asyncio.sleep(30)
        if failure == "protocol_error":
            raise ValueError("synthetic invalid clamd response")
        raise OSError("synthetic unrelated socket error")

    async def fake_cli(_target: Path, *, profile):
        nonlocal cli_calls
        cli_calls += 1
        return f"{target}: OK\n", 0

    monkeypatch.setattr(engine, "_scan_socket", failing_socket)
    monkeypatch.setattr(engine, "_run_cli_scan", fake_cli)

    result = await engine.scan(target)

    assert cli_calls == 0
    assert result.status.name == ("TIMEOUT" if failure == "timeout" else "ERROR")
    if failure == "timeout":
        assert result.engine == "clamd"


@pytest.mark.asyncio
async def test_cancelling_clamd_scan_does_not_start_cli_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Cancellation remains distinct from a recoverable clamd failure."""
    target = tmp_path / "sample.bin"
    target.write_bytes(b"sample")
    socket_path = tmp_path / "clamd.ctl"
    socket_path.touch()
    engine = ClamAVEngine(socket_path=socket_path)
    socket_started = asyncio.Event()
    never = asyncio.Event()
    cli_calls = 0

    async def blocked_socket(_target: Path, _profile, response_buffer=None):
        socket_started.set()
        await never.wait()
        return "unused", 0, ()

    async def fake_cli(_target: Path, *, profile):
        nonlocal cli_calls
        cli_calls += 1
        return f"{target}: OK\n", 0

    monkeypatch.setattr(engine, "_scan_socket", blocked_socket)
    monkeypatch.setattr(engine, "_run_cli_scan", fake_cli)

    task = asyncio.create_task(engine.scan(target))
    await asyncio.wait_for(socket_started.wait(), timeout=1)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task
    assert cli_calls == 0


def _linux_process_state(pid: int) -> str | None:
    """Return a Linux /proc process state, or None when the PID is gone."""
    try:
        stat_line = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except FileNotFoundError:
        return None
    return stat_line.rsplit(")", 1)[1].split()[0]


@pytest.mark.asyncio
async def test_process_group_termination_kills_sigterm_ignoring_descendant(
    tmp_path: Path,
) -> None:
    """The process-group helper must kill descendants even after parent exit.

    The child deliberately ignores SIGTERM. The test always SIGKILLs any
    survivor in cleanup so a regression cannot leak into the CI runner.
    """
    if not Path("/proc").is_dir():
        pytest.skip("requires Linux /proc process state")

    pid_file = tmp_path / "descendant.pid"
    child_script = (
        "import os,signal,time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"open({str(pid_file)!r}, 'w').write(str(os.getpid())); "
        "time.sleep(60)"
    )
    parent_script = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable, '-S', '-c', {child_script!r}]); "
        "time.sleep(60)"
    )
    parent = await asyncio.create_subprocess_exec(
        sys.executable,
        "-S",
        "-c",
        parent_script,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
        start_new_session=True,
    )
    child_pid: int | None = None
    try:
        for _ in range(500):
            if pid_file.is_file():
                break
            if parent.returncode is not None:
                pytest.fail("parent exited before creating its child")
            await asyncio.sleep(0.01)
        assert pid_file.is_file(), "child did not publish its PID"
        child_pid = int(pid_file.read_text(encoding="ascii"))
        child_group = os.getpgid(child_pid)
        child_session = os.getsid(child_pid)
        assert child_group == parent.pid
        assert child_session == parent.pid

        await ClamAVEngine._terminate_process(parent, grace=0.2)
        child_state = _linux_process_state(child_pid)
        for _ in range(50):
            if child_state in (None, "Z"):
                break
            await asyncio.sleep(0.02)
            child_state = _linux_process_state(child_pid)

        assert child_state in (None, "Z"), (
            f"descendant survived process-group termination: pid={child_pid}, "
            f"state={child_state}, pgrp={child_group}, session={child_session}, "
            f"leader={parent.pid}"
        )
    finally:
        if child_pid is not None:
            with contextlib.suppress(ProcessLookupError):
                os.kill(child_pid, signal.SIGKILL)
        if parent.returncode is None:
            await ClamAVEngine._terminate_process(parent, grace=0.2)


class _BlockingEngine(BaseAVEngine):
    name = "diagnostic-blocking"

    def __init__(self) -> None:
        self.first_started = asyncio.Event()
        self.release_first = asyncio.Event()
        self.scan_cancelled = asyncio.Event()
        self.targets: list[str] = []

    async def scan(self, target: Path, *, recursive: bool = True, profile=None) -> ScanResult:
        self.targets.append(str(target))
        if target.name == "first":
            self.first_started.set()
            try:
                await self.release_first.wait()
            finally:
                self.scan_cancelled.set()
        return ScanResult(target=str(target), clean=True, engine=self.name)

    async def update_signatures(self) -> str:
        return ""


@pytest.mark.asyncio
async def test_cancelled_runner_waiter_does_not_leak_concurrency_slot(
    tmp_path: Path,
) -> None:
    """A cancelled task waiting for capacity must not consume the only slot."""
    engine = _BlockingEngine()
    runner = ScanTaskRunner(engine, max_concurrency=1)

    first = asyncio.create_task(runner.submit(tmp_path / "first"))
    await asyncio.wait_for(engine.first_started.wait(), timeout=1)

    waiting = asyncio.create_task(runner.submit(tmp_path / "cancelled-waiter"))
    await asyncio.sleep(0.05)
    waiting.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiting

    engine.release_first.set()
    first_result = await asyncio.wait_for(first, timeout=1)
    third_result = await asyncio.wait_for(
        runner.submit(tmp_path / "third"),
        timeout=1,
    )

    assert first_result.clean is True
    assert third_result.clean is True
    assert engine.targets == [str(tmp_path / "first"), str(tmp_path / "third")]


@pytest.mark.asyncio
async def test_scheduler_stop_cancels_in_flight_scan(
    tmp_path: Path,
) -> None:
    """Stopping the scheduler propagates cancellation into the active scan."""
    engine = _BlockingEngine()
    settings = SettingsStore(tmp_path / "settings.json")
    settings.save(
        AppSettings(
            scheduled_scans_enabled=True,
            scheduled_hour=0,
            scheduled_minute=0,
        )
    )
    manager = ScheduledScanManager(
        ScanTaskRunner(engine),
        settings,
        default_target=tmp_path / "first",
    )

    await manager.start()
    try:
        await asyncio.wait_for(engine.first_started.wait(), timeout=2)
        await manager.stop()
        assert engine.scan_cancelled.is_set()
        assert manager.is_running is False
    finally:
        if manager.is_running:
            await manager.stop()
        engine.release_first.set()



class _PartialClamdReader:
    """Deliver one detection line, then block or raise a transport failure."""

    def __init__(self, payload: bytes, *, fail_after_payload: bool = False) -> None:
        self.payload = payload
        self.fail_after_payload = fail_after_payload
        self.delivered = asyncio.Event()
        self._sent = False

    async def read(self, _size: int) -> bytes:
        if not self._sent:
            self._sent = True
            self.delivered.set()
            return self.payload
        if self.fail_after_payload:
            raise ConnectionResetError("synthetic clamd transport reset")
        await asyncio.Event().wait()
        return b""


class _PartialClamdWriter:
    def write(self, _data: bytes) -> None:
        pass

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        return None


def _install_partial_clamd(
    monkeypatch: pytest.MonkeyPatch,
    *,
    payload: bytes,
    fail_after_payload: bool = False,
) -> _PartialClamdReader:
    reader = _PartialClamdReader(payload, fail_after_payload=fail_after_payload)

    async def open_connection(_path: str):
        return reader, _PartialClamdWriter()

    monkeypatch.setattr(asyncio, "open_unix_connection", open_connection)
    return reader


@pytest.mark.asyncio
async def test_clamd_timeout_preserves_partial_detections(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "sample.bin"
    target.write_bytes(b"sample")
    detection = f"{target}: Eicar-Test-Signature FOUND"
    reader = _install_partial_clamd(monkeypatch, payload=(detection + "\n").encode())
    socket_path = tmp_path / "clamd.ctl"
    socket_path.touch()
    engine = ClamAVEngine(socket_path=socket_path, command_timeout=0.05)

    result = await engine.scan(target)

    assert reader.delivered.is_set()
    assert result.status.name == "TIMEOUT"
    assert result.clean is False
    assert result.engine == "clamd"
    assert detection in result.threats
    assert detection in result.metadata["partial_output"]


@pytest.mark.asyncio
async def test_clamd_cancellation_preserves_partial_detections(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "sample.bin"
    target.write_bytes(b"sample")
    detection = f"{target}: Eicar-Test-Signature FOUND"
    reader = _install_partial_clamd(monkeypatch, payload=(detection + "\n").encode())
    socket_path = tmp_path / "clamd.ctl"
    socket_path.touch()
    engine = ClamAVEngine(socket_path=socket_path, command_timeout=5.0)

    task = asyncio.create_task(engine.scan(target))
    await asyncio.wait_for(reader.delivered.wait(), timeout=1.0)
    task.cancel()

    with pytest.raises(asyncio.CancelledError) as cancelled:
        await task

    assert detection in getattr(cancelled.value, "partial_output", "")


@pytest.mark.asyncio
async def test_clamd_transport_error_preserves_partial_detections(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "sample.bin"
    target.write_bytes(b"sample")
    detection = f"{target}: Eicar-Test-Signature FOUND"
    _install_partial_clamd(
        monkeypatch,
        payload=(detection + "\n").encode(),
        fail_after_payload=True,
    )
    socket_path = tmp_path / "clamd.ctl"
    socket_path.touch()
    engine = ClamAVEngine(socket_path=socket_path)

    result = await engine.scan(target)

    assert result.status.name == "ERROR"
    assert result.clean is False
    assert result.engine == "clamd"
    assert detection in result.threats
    assert detection in result.metadata["partial_output"]


def test_clamav_engine_preserves_legacy_sixth_positional_argument() -> None:
    engine = ClamAVEngine(
        Path("/nonexistent/clamd.ctl"),
        "clamscan",
        "freshclam",
        False,
        300.0,
        8,
    )

    assert engine.max_descriptor_workers == 8
    assert engine.command_inactivity_timeout == 600.0
    assert engine.command_maximum_timeout == 3600.0
