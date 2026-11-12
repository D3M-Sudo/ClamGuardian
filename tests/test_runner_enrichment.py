"""Tests for best-effort shared scan-result enrichment."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from clamguardian.core.base import BaseAVEngine, ScanResult
from clamguardian.core.profiles import ScanProfile
from clamguardian.core.runner import ScanTaskRunner

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class StubEngine(BaseAVEngine):
    name = "stub"

    async def scan(
        self,
        target: Path,
        *,
        recursive: bool = True,
        profile: ScanProfile | None = None,
    ) -> ScanResult:
        return ScanResult(
            target=str(target),
            clean=True,
            engine=self.name,
            metadata={"sha256": SHA256},
        )

    async def update_signatures(self) -> str:
        return "updated"


@pytest.mark.asyncio
async def test_runner_applies_enrichment_before_returning_scan_result(tmp_path) -> None:
    runner = ScanTaskRunner(StubEngine())
    calls = 0

    async def enrich(result: ScanResult) -> None:
        nonlocal calls
        calls += 1
        result.metadata["threat_intelligence"] = '{"provider":"virustotal"}'

    runner.set_result_enricher(enrich)
    result = await runner.submit(tmp_path / "sample.bin")

    assert calls == 1
    assert result.clean is True
    assert result.metadata["sha256"] == SHA256
    assert result.metadata["threat_intelligence"] == '{"provider":"virustotal"}'


@pytest.mark.asyncio
async def test_enrichment_failure_does_not_change_local_av_result(tmp_path, caplog) -> None:
    runner = ScanTaskRunner(StubEngine())

    async def fail(_result: ScanResult) -> None:
        raise RuntimeError("remote service unavailable")

    runner.set_result_enricher(fail)
    result = await runner.submit(tmp_path / "sample.bin")

    assert result.clean is True
    assert result.metadata["sha256"] == SHA256
    assert "preserving AV result" in caplog.text


@pytest.mark.asyncio
async def test_cancelling_enrichment_cancels_the_submitted_task(tmp_path) -> None:
    runner = ScanTaskRunner(StubEngine())
    entered = asyncio.Event()
    release = asyncio.Event()

    async def blocked(_result: ScanResult) -> None:
        entered.set()
        await release.wait()

    runner.set_result_enricher(blocked)
    task = asyncio.create_task(runner.submit(tmp_path / "sample.bin"))
    await entered.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0)
    assert runner.active_count == 0


@pytest.mark.asyncio
async def test_remote_enrichment_does_not_hold_av_concurrency_slot(tmp_path) -> None:
    runner = ScanTaskRunner(StubEngine(), max_concurrency=1)
    first_entered = asyncio.Event()
    release_first = asyncio.Event()
    first_target = tmp_path / "first.bin"

    async def enrich(result: ScanResult) -> None:
        if result.target == str(first_target):
            first_entered.set()
            await release_first.wait()

    runner.set_result_enricher(enrich)
    first = asyncio.create_task(runner.submit(first_target))
    await first_entered.wait()

    second = asyncio.create_task(runner.submit(tmp_path / "second.bin"))
    second_result = await asyncio.wait_for(second, timeout=1)

    assert second_result.clean is True
    assert not first.done()
    release_first.set()
    assert (await first).clean is True


@pytest.mark.asyncio
async def test_descriptor_scan_uses_same_enrichment_hook(tmp_path) -> None:
    engine = StubEngine()
    target = tmp_path / "descriptor.bin"
    scan_calls: list[tuple[int, Path, ScanProfile | None]] = []

    async def scan_fd(
        fd: int, *, target: Path, profile: ScanProfile | None = None
    ) -> ScanResult:
        scan_calls.append((fd, target, profile))
        return ScanResult(
            target=str(target), clean=True, engine=engine.name,
            metadata={"sha256": SHA256},
        )

    engine.scan_fd = scan_fd
    runner = ScanTaskRunner(engine)
    enriched: list[str] = []

    async def enrich(result: ScanResult) -> None:
        enriched.append(result.target)
        result.metadata["threat_intelligence"] = '{"provider":"virustotal"}'

    runner.set_result_enricher(enrich)
    result = await runner.submit_fd(17, target, profile=ScanProfile.home())

    assert scan_calls == [(17, target, ScanProfile.home())]
    assert enriched == [str(target)]
    assert result.metadata["threat_intelligence"] == '{"provider":"virustotal"}'


@pytest.mark.asyncio
async def test_descriptor_scan_fails_closed_without_engine_support(tmp_path) -> None:
    runner = ScanTaskRunner(StubEngine())
    with pytest.raises(RuntimeError, match="does not support descriptor"):
        await runner.submit_fd(17, tmp_path / "missing.bin")


def test_cancel_all_does_not_wait_on_a_stopped_event_loop() -> None:
    runner = ScanTaskRunner(StubEngine())
    stopped_loop = asyncio.new_event_loop()
    task = stopped_loop.create_task(asyncio.sleep(60))
    # Let the coroutine start before stopping its loop, avoiding an
    # un-awaited-coroutine warning when the test later disposes the task.
    stopped_loop.run_until_complete(asyncio.sleep(0))
    runner._track_task(task, stopped_loop)

    asyncio.run(runner.cancel_all())

    assert runner.active_count == 0
    assert not task.done()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        stopped_loop.run_until_complete(task)
    stopped_loop.close()
    assert runner.active_count == 0
