"""Tests for USB / removable media auto-scan module."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from clamguardian.core.base import BaseAVEngine, ScanResult, ScanStatus
from clamguardian.core.profiles import ScanProfile
from clamguardian.core.runner import ScanTaskRunner
from clamguardian.core.usb import USBDeviceScanner, USBMountMonitor, USBScanError
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
    scanner = USBDeviceScanner(runner, mount_detector=lambda _path: True)

    assert scanner.is_removable_mount(Path("/media/user/USB_STICK")) is True
    assert scanner.is_removable_mount(Path("/run/media/user/USB_STICK")) is True
    assert scanner.is_removable_mount(Path("/mnt/usb")) is True
    assert scanner.is_removable_mount(Path("/media")) is False
    assert scanner.is_removable_mount(Path("/mnt")) is False
    assert scanner.is_removable_mount(Path("/home/user/documents")) is False
    assert scanner.is_removable_mount(Path("/etc")) is False


def test_validate_target_rejection(tmp_path: Path) -> None:
    runner = ScanTaskRunner(StubEngine())
    custom_root = tmp_path / "media"
    custom_root.mkdir()
    scanner = USBDeviceScanner(
        runner,
        allowed_mount_roots=(custom_root,),
        mount_detector=lambda path: path.name == "usb_drive",
    )

    with pytest.raises(USBScanError, match="does not exist"):
        scanner.validate_target(custom_root / "missing")

    reg_file = custom_root / "file.txt"
    reg_file.write_text("hello")
    with pytest.raises(USBScanError, match="not a directory"):
        scanner.validate_target(reg_file)

    outside = tmp_path / "outside_dir"
    outside.mkdir()
    with pytest.raises(USBScanError, match="not a valid removable"):
        scanner.validate_target(outside)

    symlink_esc = custom_root / "symlink_esc"
    symlink_esc.symlink_to(outside)
    with pytest.raises(USBScanError, match="not a valid removable"):
        scanner.validate_target(symlink_esc)

    valid_mount = custom_root / "usb_drive"
    valid_mount.mkdir()
    assert scanner.validate_target(valid_mount) == valid_mount.resolve()


@pytest.mark.asyncio
async def test_usb_scan_successful_execution(tmp_path: Path) -> None:
    media_root = tmp_path / "media"
    media_root.mkdir()
    mount = media_root / "usb_drive"
    mount.mkdir()
    (mount / "file.txt").write_text("usb file")

    store = SqliteHistoryStore(tmp_path / "history.db")
    runner = ScanTaskRunner(StubEngine())
    scanner = USBDeviceScanner(runner, history_store=store, allowed_mount_roots=(media_root,))

    started: list[bool] = []
    result = await scanner.scan_device(mount, on_start=lambda: started.append(True))

    assert result.status is ScanStatus.CLEAN
    assert len(started) == 1

    records = await store.list_scans()
    assert len(records) == 1
    assert records[0].target == str(mount)


@pytest.mark.asyncio
async def test_usb_scan_duplicate_event_suppression(tmp_path: Path) -> None:
    media_root = tmp_path / "media"
    media_root.mkdir()
    mount = media_root / "usb_drive"
    mount.mkdir()

    runner = ScanTaskRunner(StubEngine(delay=0.1))
    scanner = USBDeviceScanner(
        runner, allowed_mount_roots=(media_root,), mount_detector=lambda path: path == mount.resolve()
    )

    task1 = asyncio.create_task(scanner.scan_device(mount))
    await asyncio.sleep(0.01)

    result2 = await scanner.scan_device(mount)
    result1 = await task1

    assert result1.status is ScanStatus.CLEAN
    assert result2.status is ScanStatus.ERROR
    assert "Scan already in progress" in (result2.error or "")


@pytest.mark.asyncio
async def test_usb_scan_device_disappearance_during_scan(tmp_path: Path) -> None:
    media_root = tmp_path / "media"
    media_root.mkdir()
    mount = media_root / "failing_usb"
    mount.mkdir()

    runner = ScanTaskRunner(StubEngine(fail=True))
    scanner = USBDeviceScanner(
        runner, allowed_mount_roots=(media_root,), mount_detector=lambda path: path == mount.resolve()
    )

    result = await scanner.scan_device(mount)
    assert result.status is ScanStatus.ERROR
    assert "disk unmounted unexpectedly" in (result.error or "")


@pytest.mark.asyncio
async def test_usb_mount_monitor_lifecycle(tmp_path: Path) -> None:
    media_root = tmp_path / "media"
    media_root.mkdir()
    mount = media_root / "test_usb"
    mount.mkdir()

    runner = ScanTaskRunner(StubEngine())
    scanner = USBDeviceScanner(
        runner, allowed_mount_roots=(media_root,), mount_detector=lambda path: path == mount.resolve()
    )

    scanned_results: list[ScanResult] = []
    monitor = USBMountMonitor(
        scanner,
        poll_interval=0.01,
        on_mount_scanned=lambda res: scanned_results.append(res),
    )

    simulated_mounts: set[Path] = set()
    monitor.get_current_mounts = lambda: set(simulated_mounts)

    await monitor.start()
    assert monitor._running is True

    simulated_mounts.add(mount)
    await asyncio.sleep(0.05)

    assert len(scanned_results) == 1
    assert scanned_results[0].status is ScanStatus.CLEAN

    await monitor.stop()
    assert monitor._running is False
