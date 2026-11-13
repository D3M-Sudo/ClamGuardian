"""Deterministic tests for scan cancellation and subprocess lifecycle.

No test depends on ``clamscan`` being installed: long-running subprocesses
are emulated with the Python interpreter itself, and ``Process`` behaviour
is faked where real process semantics would be flaky on CI.
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys
from pathlib import Path
from typing import Any

import pytest

from clamguardian.engines.clamav import ClamAVEngine


def _sleep_command(seconds: float = 30) -> list[str]:
    return [sys.executable, "-c", f"import time; time.sleep({seconds})"]


class _ProcessRecorder:
    """Wrapper around ``asyncio.create_subprocess_exec`` recording the child."""

    def __init__(self, original: Any) -> None:
        self._original = original
        self.processes: list[asyncio.subprocess.Process] = []

    def __call__(self, *args: Any, **kwargs: Any):
        coro = self._original(*args, **kwargs)

        async def _create() -> asyncio.subprocess.Process:
            process = await coro
            self.processes.append(process)
            return process

        return _create()


@pytest.mark.asyncio
async def test_cancellation_terminates_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """task.cancel() kills the child process and still raises CancelledError."""
    recorder = _ProcessRecorder(asyncio.create_subprocess_exec)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", recorder)
    engine = ClamAVEngine(socket_path=Path("/nonexistent/clamd.ctl"))

    task = asyncio.create_task(engine._run_command(_sleep_command()))
    await asyncio.sleep(0.2)  # let the subprocess actually start
    assert len(recorder.processes) == 1
    process = recorder.processes[0]
    assert process.returncode is None  # still running

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert process.returncode is not None  # subprocess terminated, no orphan


@pytest.mark.asyncio
async def test_cancellation_preserves_partial_subprocess_output() -> None:
    """Cancellation propagates while retaining bounded diagnostics on the exception."""
    detection = "/tmp/infected.bin: Eicar-Test-Signature FOUND"
    script = f"import time; print({detection!r}, flush=True); time.sleep(30)"
    engine = ClamAVEngine(
        socket_path=Path("/nonexistent"),
        command_inactivity_timeout=2.0,
        command_maximum_timeout=5.0,
    )
    task = asyncio.create_task(engine._run_command([sys.executable, "-c", script]))
    await asyncio.sleep(0.2)
    task.cancel()

    with pytest.raises(asyncio.CancelledError) as cancelled:
        await task

    assert detection in getattr(cancelled.value, "partial_output", "")


@pytest.mark.asyncio
async def test_stream_reader_failure_terminates_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stdout reader failure must not leave its subprocess running."""
    process = await asyncio.create_subprocess_exec(
        *_sleep_command(),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    assert process.stdout is not None

    async def fail_read(_size: int = -1) -> bytes:
        raise RuntimeError("synthetic stdout reader failure")

    process.stdout.read = fail_read  # type: ignore[method-assign]

    async def return_existing_process(*_args, **_kwargs):
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", return_existing_process)
    engine = ClamAVEngine(socket_path=Path("/nonexistent"))

    try:
        with pytest.raises(RuntimeError, match="synthetic stdout reader failure"):
            await asyncio.wait_for(engine._run_command(["synthetic-command"]), timeout=1.0)
        assert process.returncode is not None
    finally:
        if process.returncode is None:
            await ClamAVEngine._terminate_process(process, grace=0.1)


@pytest.mark.asyncio
async def test_timeout_kills_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    """command_timeout terminates the child and surfaces TimeoutError."""
    recorder = _ProcessRecorder(asyncio.create_subprocess_exec)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", recorder)
    engine = ClamAVEngine(
        socket_path=Path("/nonexistent"),
        command_inactivity_timeout=0.2,
        command_maximum_timeout=1.0,
    )

    with pytest.raises(TimeoutError):
        await engine._run_command(_sleep_command())

    assert len(recorder.processes) == 1
    assert recorder.processes[0].returncode is not None


@pytest.mark.asyncio
async def test_scan_timeout_returns_timeout_result(monkeypatch: pytest.MonkeyPatch) -> None:
    """A CLI scan timeout maps to ScanStatus.TIMEOUT, not to an error/crash."""
    engine = ClamAVEngine(socket_path=Path("/nonexistent"))

    async def fake_command(args):
        raise TimeoutError

    monkeypatch.setattr(engine, "_run_command", fake_command)
    result = await engine.scan(Path("/tmp"))
    assert result.status.name == "TIMEOUT"
    assert result.clean is False
    assert result.error is not None


@pytest.mark.asyncio
async def test_terminate_process_on_already_exited_process() -> None:
    """Terminating a reaped process is a no-op (no double kill, no error)."""
    process = await asyncio.create_subprocess_exec(*_sleep_command(0))
    await process.wait()
    assert process.returncode is not None
    await ClamAVEngine._terminate_process(process)  # must not raise
    assert process.returncode is not None


@pytest.mark.asyncio
async def test_terminate_process_reaps_parent_without_full_grace_delay() -> None:
    """A process with no descendants should not consume the entire grace period."""
    process = await asyncio.create_subprocess_exec(
        *_sleep_command(),
        start_new_session=True,
    )
    started = asyncio.get_running_loop().time()

    await ClamAVEngine._terminate_process(process, grace=1.0)

    elapsed = asyncio.get_running_loop().time() - started
    assert process.returncode is not None
    assert elapsed < 0.5


@pytest.mark.asyncio
async def test_terminate_process_escalates_to_kill() -> None:
    """A child ignoring SIGTERM is SIGKILLed after the grace period."""
    # Ignore SIGTERM explicitly, forcing the SIGKILL escalation path.
    script = (
        "import signal, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "print('ready', flush=True)\n"
        "time.sleep(30)\n"
    )
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        script,
        stdout=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    assert process.stdout is not None
    await process.stdout.readline()  # wait until SIGTERM handler is installed

    await ClamAVEngine._terminate_process(process, grace=0.2)
    assert process.returncode is not None
    assert process.returncode == -signal.SIGKILL


@pytest.mark.asyncio
async def test_terminate_process_kills_descendants_after_parent_exits(
    tmp_path: Path,
) -> None:
    """An exited session leader must not leave SIGTERM-resistant descendants."""
    pid_file = tmp_path / "descendant.pid"
    child_script = (
        "import signal, time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"open({str(pid_file)!r}, 'w').write(str(__import__('os').getpid())); "
        "time.sleep(30)"
    )
    parent_script = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {child_script!r}]); "
        "time.sleep(0.15)"
    )
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        parent_script,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    await process.wait()
    for _ in range(50):
        if pid_file.exists():
            break
        await asyncio.sleep(0.02)
    assert pid_file.exists()
    child_pid = int(pid_file.read_text())

    await ClamAVEngine._terminate_process(process, grace=0.1)

    for _ in range(50):
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        stat_path = Path(f"/proc/{child_pid}/stat")
        if stat_path.exists() and stat_path.read_text().split()[2] == "Z":
            break
        await asyncio.sleep(0.02)
    else:
        pytest.fail("descendant process survived process-group termination")


@pytest.mark.asyncio
async def test_engine_startup_failure_raises_engine_error() -> None:
    """A missing binary becomes EngineError, keeping error propagation typed."""
    from clamguardian.core.errors import EngineError

    engine = ClamAVEngine(clamscan_binary="/nonexistent/clamscan-binary")
    with pytest.raises(EngineError):
        await engine._run_command(["/nonexistent/clamscan-binary", "--version"])