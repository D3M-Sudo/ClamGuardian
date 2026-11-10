"""Integration coverage for the shared enrichment hook across scan workflows."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from clamguardian.core.base import BaseAVEngine, ScanResult
from clamguardian.core.profiles import ScanProfile
from clamguardian.core.runner import ScanTaskRunner
from clamguardian.core.scheduler import ScheduledScanManager
from clamguardian.core.settings import SettingsStore
from clamguardian.core.usb import USBDeviceScanner
from clamguardian.realtime.events import FileEvent, FileEventType
from clamguardian.realtime.orchestrator import RealtimeScanOrchestrator
from clamguardian.ui.controller import ShieldTaskController

_ENRICHED_KEY = "test_remote_evidence"


class StubEngine(BaseAVEngine):
    name = "flow-test"

    async def scan(
        self,
        target: Path,
        *,
        recursive: bool = True,
        profile: ScanProfile | None = None,
    ) -> ScanResult:
        return ScanResult(target=str(target), clean=True, engine=self.name)

    async def update_signatures(self) -> str:
        return "updated"


def _attach_enricher(runner: ScanTaskRunner, source: str) -> None:
    async def enrich(result: ScanResult) -> None:
        result.metadata[_ENRICHED_KEY] = source

    runner.set_result_enricher(enrich)


@pytest.mark.asyncio
async def test_interactive_controller_uses_shared_enrichment_hook(tmp_path) -> None:
    controller = ShieldTaskController(engine=StubEngine())
    _attach_enricher(controller._runner, "interactive")

    result = await controller.scan(tmp_path / "interactive.bin")

    assert result.clean is True
    assert result.metadata[_ENRICHED_KEY] == "interactive"


@pytest.mark.asyncio
async def test_scheduler_uses_shared_enrichment_hook(tmp_path) -> None:
    runner = ScanTaskRunner(StubEngine())
    _attach_enricher(runner, "scheduler")
    manager = ScheduledScanManager(
        runner,
        SettingsStore(tmp_path / "settings.json"),
        default_target=tmp_path,
    )

    result = await manager.trigger_now()

    assert result.clean is True
    assert result.metadata[_ENRICHED_KEY] == "scheduler"


@pytest.mark.asyncio
async def test_usb_scan_uses_shared_enrichment_hook(tmp_path) -> None:
    media_root = tmp_path / "media"
    mount = media_root / "usb"
    mount.mkdir(parents=True)
    runner = ScanTaskRunner(StubEngine())
    _attach_enricher(runner, "usb")
    scanner = USBDeviceScanner(
        runner,
        allowed_mount_roots=(media_root,),
        mount_detector=lambda candidate: candidate == mount.resolve(),
    )

    result = await scanner.scan_device(mount)

    assert result.clean is True
    assert result.metadata[_ENRICHED_KEY] == "usb"


@pytest.mark.asyncio
async def test_realtime_path_scan_uses_shared_enrichment_hook(tmp_path) -> None:
    target = tmp_path / "realtime.txt"
    target.write_text("realtime test")
    runner = ScanTaskRunner(StubEngine())
    _attach_enricher(runner, "realtime")
    orchestrator = RealtimeScanOrchestrator(runner, debounce_seconds=0.01)
    completed: list[ScanResult] = []
    done = asyncio.Event()

    def on_complete(result: ScanResult) -> None:
        completed.append(result)
        done.set()

    await orchestrator.handle_events(
        [FileEvent(path=target, event_type=FileEventType.CREATE)],
        on_scan_complete=on_complete,
    )
    await asyncio.wait_for(done.wait(), timeout=2)
    await orchestrator.close()

    assert completed[0].clean is True
    assert completed[0].metadata[_ENRICHED_KEY] == "realtime"
