"""Tests for USB / removable media auto-scan module."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from clamguardian.core.base import BaseAVEngine, ScanResult, ScanStatus
from clamguardian.core.profiles import ScanProfile
from clamguardian.core.runner import ScanTaskRunner
from clamguardian.core.usb import USBDeviceScanner
from clamguardian.history import SqliteHistoryStore


class StubEngine(BaseAVEngine):
    name = "stub"

    def __init__(self, delay: float = 0.01, fail: bool = False) -> None:
        self.delay = delay
        self.fail = fail

    async def scan(
        self, target: Path, *, recursive: bool = True, profile: ScanProfile | None = None
    ) -> ScanResult:
        await asyncio.sleep(self.delay)
        if self.fail:
            raise RuntimeError("disk unmounted unexpectedly")
        return ScanResult(target=str(target), clean=True, metadata={"sha256": "abcdef123456"})

    async def update_signatures(self) -> str:
        return ""


def test_is_removable_mount_detection(tmp_path: Path) -> None:
    runner = ScanTaskRunner(StubEngine())
    scanner = USBDeviceScanner(runner)

    assert scanner.is_removable_mount(Path("/media/user/USB_STICK")) is True
    assert scanner.is_removable_mount(Path("/run/media/user/USB_STICK")) is True
    assert scanner.is_removable_mount(Path("/mnt/usb")) is True
    assert scanner.is_removable_mount(Path("/home/user/documents")) is False


@pytest.mark.asyncio
async def test_usb_scan_successful_execution(tmp_path: Path) -> None:
    mount = tmp_path / "usb_drive"
    mount.mkdir()
    (mount / "file.txt").write_text("usb file")

    store = SqliteHistoryStore(tmp_path / "history.db")
    runner = ScanTaskRunner(StubEngine())
    scanner = USBDeviceScanner(runner, history_store=store)

    started: list[bool] = []
    result = await scanner.scan_device(mount, on_start=lambda: started.append(True))

    assert result.status is ScanStatus.CLEAN
    assert len(started) == 1

    records = await store.list_scans()
    assert len(records) == 1
    assert records[0].target == str(mount)


@pytest.mark.asyncio
async def test_usb_scan_nonexistent_target(tmp_path: Path) -> None:
    missing = tmp_path / "nonexistent_usb"
    runner = ScanTaskRunner(StubEngine())
    scanner = USBDeviceScanner(runner)

    result = await scanner.scan_device(missing)
    assert result.status is ScanStatus.ERROR
    assert "does not exist" in (result.error or "")


@pytest.mark.asyncio
async def test_usb_scan_nondirectory_target(tmp_path: Path) -> None:
    regular_file = tmp_path / "not_a_mount.txt"
    regular_file.write_text("file")

    runner = ScanTaskRunner(StubEngine())
    scanner = USBDeviceScanner(runner)

    result = await scanner.scan_device(regular_file)
    assert result.status is ScanStatus.ERROR
    assert "not a directory" in (result.error or "")


@pytest.mark.asyncio
async def test_usb_scan_duplicate_event_suppression(tmp_path: Path) -> None:
    mount = tmp_path / "usb_drive"
    mount.mkdir()

    runner = ScanTaskRunner(StubEngine(delay=0.1))
    scanner = USBDeviceScanner(runner)

    task1 = asyncio.create_task(scanner.scan_device(mount))
    await asyncio.sleep(0.01)  # let task1 acquire active mount

    result2 = await scanner.scan_device(mount)
    result1 = await task1

    assert result1.status is ScanStatus.CLEAN
    assert result2.status is ScanStatus.ERROR
    assert "Scan already in progress" in (result2.error or "")


@pytest.mark.asyncio
async def test_usb_scan_device_disappearance_during_scan(tmp_path: Path) -> None:
    mount = tmp_path / "failing_usb"
    mount.mkdir()

    runner = ScanTaskRunner(StubEngine(fail=True))
    scanner = USBDeviceScanner(runner)

    result = await scanner.scan_device(mount)
    assert result.status is ScanStatus.ERROR
    assert "disk unmounted unexpectedly" in (result.error or "")
