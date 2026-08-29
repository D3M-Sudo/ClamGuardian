"""Tests for core scan models and task runner lifecycle."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from clamguardian.core.base import BaseAVEngine, ScanProgress, ScanResult, ScanStatus
from clamguardian.core.errors import EngineError
from clamguardian.core.runner import ScanTaskRunner

# ---------------------------------------------------------------------------
# ScanResult / ScanProgress models
# ---------------------------------------------------------------------------


def test_scan_result_status_per_state() -> None:
    started = datetime.now(UTC)
    finished = started + timedelta(seconds=2)

    clean = ScanResult(target="/tmp/x", clean=True, started_at=started, finished_at=finished)
    assert clean.status is ScanStatus.CLEAN and clean.clean is True

    infected = ScanResult(
        target="/tmp/x", clean=False, threats=("Eicar FOUND",), started_at=started
    )
    assert infected.status is ScanStatus.INFECTED and infected.clean is False

    error = ScanResult(target="/tmp/x", clean=False, error="boom", started_at=started)
    assert error.status is ScanStatus.ERROR and error.error == "boom"

    cancelled = ScanResult.cancelled("/tmp/x", started)
    assert cancelled.status is ScanStatus.CANCELLED and cancelled.clean is False

    timed_out = ScanResult.timed_out("/tmp/x", started)
    assert timed_out.status is ScanStatus.TIMEOUT and timed_out.error == "scan timed out"

    assert clean.duration_seconds == pytest.approx(2.0)
    assert infected.duration_seconds >= 0.0


def test_scan_result_legacy_clean_flag_is_normalized() -> None:
    """Passing only the legacy ``clean`` boolean keeps status consistent."""
    result = ScanResult(target="/x", clean=False)
    assert result.status is ScanStatus.CLEAN  # no threats, no error => clean
    assert result.clean is True


def test_scan_progress_defaults_and_optional_percent() -> None:
    progress = ScanProgress()
    assert progress.percent is None  # percentage is optional by design
    assert progress.phase == "scanning"
    filled = ScanProgress(
        phase="scanning",
        files_scanned=10,
        bytes_scanned=2048,
        current_path="/tmp/a",
        threats_found=1,
        elapsed_seconds=1.5,
        percent=42.0,
    )
    assert filled.threats_found == 1 and filled.current_path == "/tmp/a"


# ---------------------------------------------------------------------------
# ScanTaskRunner lifecycle
# ---------------------------------------------------------------------------


class FakeEngine(BaseAVEngine):
    name = "fake"

    def __init__(self, delay: float = 0.05, fail: bool = False) -> None:
        self.delay = delay
        self.fail = fail
        self.started = 0
        self.finished = 0
        self.cancelled = 0

    async def scan(
        self, target: Path, *, recursive: bool = True, profile: object = None
    ) -> ScanResult:
        self.started += 1
        try:
            await asyncio.sleep(self.delay)
            if self.fail:
                raise EngineError("engine exploded")
            return ScanResult(target=str(target), clean=True)
        except asyncio.CancelledError:
            self.cancelled += 1
            raise
        finally:
            self.finished += 1

    async def update_signatures(self) -> str:
        return ""


@pytest.mark.asyncio
async def test_runner_task_is_unregistered_after_completion() -> None:
    runner = ScanTaskRunner(FakeEngine(delay=0.01))
    task = runner.create_task(Path("/tmp/a"))
    result = await task
    assert result.status is ScanStatus.CLEAN
    await asyncio.sleep(0)  # let done callbacks run
    assert runner.active_count == 0
    assert not runner._tasks


@pytest.mark.asyncio
async def test_runner_task_removed_after_failure() -> None:
    runner = ScanTaskRunner(FakeEngine(fail=True))
    task = runner.create_task(Path("/tmp/a"))
    with pytest.raises(EngineError):
        await task
    await asyncio.sleep(0)
    assert runner.active_count == 0


@pytest.mark.asyncio
async def test_runner_cancel_all_propagates_and_cleans_up() -> None:
    engine = FakeEngine(delay=5)
    runner = ScanTaskRunner(engine, max_concurrency=4)
    tasks = [runner.create_task(Path(f"/tmp/{i}")) for i in range(3)]
    await asyncio.sleep(0.01)
    assert runner.active_count == 3
    await runner.cancel_all()
    assert all(task.cancelled() for task in tasks)
    assert runner.active_count == 0
    assert engine.cancelled == 3
    assert engine.finished == 3  # cleanup ran in finally


@pytest.mark.asyncio
async def test_runner_cancel_before_start_never_runs_engine() -> None:
    runner = ScanTaskRunner(FakeEngine())
    started: list[str] = []
    task = runner.create_task(Path("/tmp/a"), on_start=lambda: started.append("x"))
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0)
    assert started == []
    assert runner.active_count == 0


@pytest.mark.asyncio
async def test_runner_concurrency_limit_and_on_start() -> None:
    engine = FakeEngine(delay=0.01)
    runner = ScanTaskRunner(engine, max_concurrency=1)
    started: list[str] = []
    tasks = [
        runner.create_task(Path(f"/tmp/{i}"), on_start=lambda: started.append("x"))
        for i in range(3)
    ]
    results = await asyncio.gather(*tasks)
    assert len(results) == 3
    assert len(started) == 3  # exactly once per scan, when actually running
    with pytest.raises(ValueError):
        ScanTaskRunner(engine, max_concurrency=0)


@pytest.mark.asyncio
async def test_runner_concurrent_scans_are_independent() -> None:
    engine = FakeEngine(delay=0.02)
    runner = ScanTaskRunner(engine, max_concurrency=2)
    results = await asyncio.gather(runner.submit(Path("/tmp/a")), runner.submit(Path("/tmp/b")))
    assert all(r.clean for r in results)
    assert engine.started == 2


# ---------------------------------------------------------------------------
# ShieldTaskController signal semantics
# ---------------------------------------------------------------------------

gi = pytest.importorskip("gi")
gi.require_version("GObject", "2.0")
from clamguardian.ui.controller import ShieldTaskController  # noqa: E402


class SignalRecorder:
    def __init__(self, controller: ShieldTaskController) -> None:
        self.events: list[tuple[str, tuple[object, ...]]] = []
        for signal_name in ("scan-started", "scan-finished", "threat-detected", "scan-cancelled"):
            controller.connect(signal_name, self._make_cb(signal_name))

    def _make_cb(self, signal_name: str):
        def cb(_obj, *args):
            self.events.append((signal_name, args))

        return cb


class StubEngine(FakeEngine):
    def __init__(self, threats: tuple[str, ...] = (), fail: bool = False) -> None:
        super().__init__(delay=0.01, fail=fail)
        self.threats = threats

    async def scan(
        self, target: Path, *, recursive: bool = True, profile: object = None
    ) -> ScanResult:
        self.started += 1
        try:
            await asyncio.sleep(self.delay)
            if self.fail:
                raise EngineError("engine exploded")
            return ScanResult(target=str(target), clean=not self.threats, threats=self.threats)
        except asyncio.CancelledError:
            self.cancelled += 1
            raise


@pytest.mark.asyncio
async def test_controller_emits_started_threats_finished_in_order() -> None:
    controller = ShieldTaskController(StubEngine(threats=("Eicar FOUND",)))
    recorder = SignalRecorder(controller)
    result = await controller.scan(Path("/tmp/evil"))
    names = [name for name, _ in recorder.events]
    assert names == ["scan-started", "threat-detected", "scan-finished"]
    assert recorder.events[1][1] == ("/tmp/evil", "Eicar FOUND")
    assert result.status is ScanStatus.INFECTED


@pytest.mark.asyncio
async def test_controller_clean_scan_has_no_threat_signal() -> None:
    controller = ShieldTaskController(StubEngine())
    recorder = SignalRecorder(controller)
    await controller.scan(Path("/tmp/ok"))
    assert [name for name, _ in recorder.events] == ["scan-started", "scan-finished"]


@pytest.mark.asyncio
async def test_controller_cancellation_emits_scan_cancelled() -> None:
    controller = ShieldTaskController(StubEngine())
    recorder = SignalRecorder(controller)
    task = asyncio.create_task(controller.scan(Path("/tmp/slow")))
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    names = [name for name, _ in recorder.events]
    assert "scan-cancelled" in names
    assert "scan-finished" not in names  # cancelled is distinct from finished


@pytest.mark.asyncio
async def test_controller_engine_error_propagates_without_finished() -> None:
    controller = ShieldTaskController(StubEngine(fail=True))
    recorder = SignalRecorder(controller)
    with pytest.raises(EngineError):
        await controller.scan(Path("/tmp/x"))
    names = [name for name, _ in recorder.events]
    assert "scan-finished" not in names
    assert "scan-cancelled" not in names


@pytest.mark.asyncio
async def test_controller_cancel_all_cancels_active_scans() -> None:
    controller = ShieldTaskController(StubEngine())
    recorder = SignalRecorder(controller)
    task = asyncio.create_task(controller.scan(Path("/tmp/slow")))
    await asyncio.sleep(0)
    cancel_task = controller.cancel_all()
    with pytest.raises(asyncio.CancelledError):
        await task
    await cancel_task
    assert "scan-cancelled" in [name for name, _ in recorder.events]