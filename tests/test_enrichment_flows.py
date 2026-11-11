"""Integration coverage for the shared enrichment hook across scan workflows."""

from __future__ import annotations

import asyncio
import json
import os
import stat
from pathlib import Path

import pytest

from clamguardian.core.base import BaseAVEngine, ScanResult
from clamguardian.core.profiles import ScanProfile
from clamguardian.core.runner import ScanTaskRunner
from clamguardian.core.scheduler import ScheduledScanManager
from clamguardian.core.settings import SettingsStore
from clamguardian.core.usb import USBDeviceScanner
from clamguardian.history import SqliteHistoryStore
from clamguardian.realtime.events import FileEvent, FileEventType
from clamguardian.realtime.orchestrator import RealtimeScanOrchestrator
from clamguardian.realtime.policy import RealtimePolicy
from clamguardian.realtime.security import open_root_directory
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

    async def scan_fd(
        self, fd: int, *, target: Path, profile: ScanProfile | None = None
    ) -> ScanResult:
        os.fstat(fd)
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
    root_fd = open_root_directory(tmp_path)
    orchestrator = RealtimeScanOrchestrator(
        runner,
        policy=RealtimePolicy(authorized_roots=[tmp_path]),
        debounce_seconds=0.01,
        root_fds={tmp_path: root_fd},
    )
    completed: list[ScanResult] = []
    done = asyncio.Event()

    def on_complete(result: ScanResult) -> None:
        completed.append(result)
        done.set()

    await orchestrator.handle_events(
        [FileEvent(path=target, event_type=FileEventType.CREATE)],
        on_scan_complete=on_complete,
    )
    try:
        await asyncio.wait_for(done.wait(), timeout=2)
    finally:
        await orchestrator.close()
        os.close(root_fd)

    assert completed[0].clean is True
    assert completed[0].metadata[_ENRICHED_KEY] == "realtime"


@pytest.mark.asyncio
async def test_realtime_descriptor_scan_end_to_end_with_enrichment_and_history(
    tmp_path: Path,
) -> None:
    """inotify → descriptor scan → enrichment → history persistence.

    Verifica che:
      * il descriptor aperto (fd) venga passato all'engine senza pathname fallback;
      * il profilo catturato sia propagato nell'envelope di enrichment;
      * l'evidenza venga persista nello store storico.
    """
    target = tmp_path / "realtime-e2e.txt"
    target.write_bytes(b"realtime e2e fixture")

    root_fd = open_root_directory(tmp_path)

    class Engine(BaseAVEngine):
        name = "realtime-fd"

        def __init__(self) -> None:
            self.scan_fd_calls: list[tuple[int, Path, ScanProfile | None]] = []
            self.scanned_identity: tuple[int, int, int] | None = None

        async def scan(
            self,
            target: Path,
            *,
            recursive: bool = True,
            profile: ScanProfile | None = None,
        ) -> ScanResult:
            raise RuntimeError("pathname scan must not be used")

        async def scan_fd(
            self, fd: int, *, target: Path, profile: ScanProfile | None = None
        ) -> ScanResult:
            self.scan_fd_calls.append((fd, target, profile))
            fstat = os.fstat(fd)
            self.scanned_identity = (fstat.st_dev, fstat.st_ino, fstat.st_mode)
            assert stat.S_ISREG(fstat.st_mode), "fd must be a regular file"
            tstat = os.stat(target)
            assert fstat.st_ino == tstat.st_ino and fstat.st_dev == tstat.st_dev, (
                "fd must point at the watched target file"
            )
            return ScanResult(
                target=str(target),
                clean=True,
                engine=self.name,
                metadata={
                    "sha256": (
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    )
                },
            )

        async def update_signatures(self) -> str:
            return "updated"

    engine = Engine()
    runner = ScanTaskRunner(engine)
    history_store = SqliteHistoryStore(tmp_path / "history.db")

    async def enrich(result: ScanResult) -> None:
        result.metadata["threat_intelligence"] = json.dumps(
            {
                "provider": "virustotal",
                "profile": "premium",
                "sha256": result.metadata["sha256"],
                "status": "found",
                "metadata": {"found": True},
            }
        )

    runner.set_result_enricher(enrich)

    orchestrator = RealtimeScanOrchestrator(
        runner,
        policy=RealtimePolicy(authorized_roots=[tmp_path]),
        history_store=history_store,
        profile=ScanProfile.home(),
        debounce_seconds=0.01,
        max_queue_depth=100,
        root_fds={tmp_path: root_fd},
    )

    completed: list[ScanResult] = []
    done = asyncio.Event()

    def on_complete(result: ScanResult) -> None:
        completed.append(result)
        done.set()

    await orchestrator.handle_events(
        [FileEvent(path=target, event_type=FileEventType.CREATE)],
        on_scan_complete=on_complete,
    )
    try:
        await asyncio.wait_for(done.wait(), timeout=5)
    finally:
        await orchestrator.close()
        os.close(root_fd)

    # Verifica: il descriptor è stato usato per la scansione (nessun pathname fallback)
    assert len(engine.scan_fd_calls) == 1
    _fd, fd_target, fd_profile = engine.scan_fd_calls[0]
    assert fd_target == target
    assert fd_profile is not None
    assert fd_profile.id == "home"
    assert engine.scanned_identity is not None
    device, inode, mode = engine.scanned_identity
    assert stat.S_ISREG(mode)
    target_stat = os.stat(target)
    assert (device, inode) == (target_stat.st_dev, target_stat.st_ino)

    # Verifica: enrichment applicato tramite il percorso condiviso ScanTaskRunner
    assert len(completed) == 1
    result = completed[0]
    assert result.clean is True
    assert result.metadata.get("threat_intelligence") is not None

    # ClamAV scan profile and VirusTotal API profile are independent contracts.
    evidence = json.loads(result.metadata["threat_intelligence"])
    assert evidence["profile"] == "premium"
    assert evidence["sha256"] == result.metadata["sha256"]

    # Verify history persistence independently from the ClamAV verdict.
    records = await history_store.list_scans()
    persisted = next(record for record in records if record.target == str(target))
    assert persisted.profile_id == "home"
    assert persisted.metadata.get("threat_intelligence") is not None
