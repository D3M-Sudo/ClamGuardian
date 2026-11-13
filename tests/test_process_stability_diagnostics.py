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
        "#!/usr/bin/env python3\\n"
        "import time\\n"
        "for _ in range(12):\\n"
        "    print('Downloading database: progress', flush=True)\\n"
        "    time.sleep(0.03)\\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    engine = ClamAVEngine(
        freshclam_binary=str(executable),
        command_inactivity_timeout=0.12,
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
        "#!/usr/bin/env python3\\n"
        "import time\\n"
        "while True:\\n"
        "    print('Downloading database: progress', flush=True)\\n"
        "    time.sleep(0.02)\\n",
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
async def test_cli_command_bounds_output_but_preserves_late_detections() -> None:
    """Output retention is bounded while detections after the cap remain visible."""
    limit = 1024
    detection = "/tmp/infected.bin: Eicar-Test-Signature FOUND"
    script = (
        "import sys\\n"
        "sys.stdout.write('O' * 4096 + '\\\\n')\\n"
        "sys.stdout.flush()\\n"
        f"sys.stderr.write('E' * 4096 + '\\\\n{detection}\\\\n')\\n"
        "sys.stderr.flush()\\n"
    )
    engine = ClamAVEngine(command_max_output_bytes=limit)

    output, exit_code = await engine._run_command([sys.executable, "-S", "-c", script])

    assert exit_code == 0
    assert len(output.encode("utf-8")) <= limit + len(detection.encode("utf-8")) + 128
    assert detection in output
    assert "OUTPUT_TRUNCATED" in output
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

    async def refused_socket(_target: Path, _profile):
        raise ConnectionRefusedError("synthetic clamd connection refusal")

    async def fake_cli(_target: Path, *, profile):
        nonlocal cli_calls
        cli_calls += 1
        return f"{target}: OK\\n", 0

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

    async def failing_socket(_target: Path, _profile):
        if failure == "timeout":
            await asyncio.sleep(30)
        if failure == "protocol_error":
            raise ValueError("synthetic invalid clamd response")
        raise OSError("synthetic unrelated socket error")

    async def fake_cli(_target: Path, *, profile):
        nonlocal cli_calls
        cli_calls += 1
        return f"{target}: OK\\n", 0

    monkeypatch.setattr(engine, "_scan_socket", failing_socket)
    monkeypatch.setattr(engine, "_run_cli_scan", fake_cli)

    result = await engine.scan(target)

    assert cli_calls == 0
    assert result.status.name == ("TIMEOUT" if failure == "timeout" else "ERROR")


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

    async def blocked_socket(_target: Path, _profile):
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
async def test_process_group_termination_can_leave_sigterm_ignoring_descendant(
    tmp_path: Path,
) -> None:
    """Characterize whether waiting for the parent also reaps its descendants.

    The child deliberately ignores SIGTERM. The test always SIGKILLs it in
    cleanup so a confirmed orphan cannot leak into the CI runner.
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

        await ClamAVEngine._terminate_process(parent, grace=0.2)
        child_state = _linux_process_state(child_pid)

        # This is a characterization assertion, not an endorsement: the
        # current implementation waits for the direct child only. If this
        # assertion holds, the report must record a surviving descendant.
        assert child_state not in (None, "Z"), (
            "the descendant was terminated; update this diagnostic if the "
            "production lifecycle has changed"
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
