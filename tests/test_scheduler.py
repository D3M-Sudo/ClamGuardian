"""Tests for scheduled scans and autostart functionality."""

from __future__ import annotations

from datetime import datetime, time
from pathlib import Path

import pytest

from clamguardian.core.autostart import AutostartManager
from clamguardian.core.base import BaseAVEngine, ScanResult, ScanStatus
from clamguardian.core.profiles import ScanProfile
from clamguardian.core.runner import ScanTaskRunner
from clamguardian.core.scheduler import ScheduledScanManager
from clamguardian.core.settings import AppSettings, SettingsStore


class StubEngine(BaseAVEngine):
    name = "stub"

    def __init__(self) -> None:
        self.scans_run: list[str] = []

    async def scan(
        self, target: Path, *, recursive: bool = True, profile: ScanProfile | None = None
    ) -> ScanResult:
        self.scans_run.append(str(target))
        return ScanResult(target=str(target), clean=True)

    async def update_signatures(self) -> str:
        return ""


def test_autostart_manager_lifecycle(tmp_path: Path) -> None:
    autostart_dir = tmp_path / "autostart"
    manager = AutostartManager(autostart_dir=autostart_dir)

    assert manager.is_enabled() is False
    manager.enable()
    assert manager.is_enabled() is True
    assert (autostart_dir / "io.github.clamguardian.ClamGuardian.desktop").is_file()

    manager.disable()
    assert manager.is_enabled() is False


@pytest.mark.asyncio
async def test_scheduled_scan_manager(tmp_path: Path) -> None:
    settings_file = tmp_path / "settings.json"
    store = SettingsStore(settings_file)
    store.save(
        AppSettings(
            scheduled_scans_enabled=True,
            scheduled_hour=datetime.now().hour,
            scheduled_minute=datetime.now().minute,
        )
    )

    engine = StubEngine()
    runner = ScanTaskRunner(engine)
    scan_target = tmp_path / "home"
    scan_target.mkdir()

    completed: list[ScanResult] = []
    manager = ScheduledScanManager(
        runner,
        store,
        default_target=scan_target,
        on_scan_complete=completed.append,
    )

    assert manager.is_enabled() is True
    sched_time = manager.get_schedule_time()
    assert isinstance(sched_time, time)

    # Trigger manual execution
    result = await manager.trigger_now()
    assert result.clean is True
    assert len(completed) == 1
    assert len(engine.scans_run) == 1

    # Test loop start/stop
    await manager.start()
    assert manager.is_running is True
    await manager.stop()
    assert manager.is_running is False


def test_scheduler_last_run_date_persists_across_restart(tmp_path: Path) -> None:
    store = SettingsStore(tmp_path / "settings.json")
    runner = ScanTaskRunner(StubEngine())
    first = ScheduledScanManager(runner, store, default_target=tmp_path)
    first._save_last_run_date("2026-11-09")

    restarted = ScheduledScanManager(runner, store, default_target=tmp_path)
    assert restarted._last_run_date == "2026-11-09"


def test_autostart_fails_closed_inside_flatpak(tmp_path: Path, monkeypatch) -> None:
    manager = AutostartManager(autostart_dir=tmp_path / "autostart")
    monkeypatch.setattr(AutostartManager, "_inside_flatpak", staticmethod(lambda: True))
    with pytest.raises(RuntimeError, match="cannot be installed from the Flatpak sandbox"):
        manager.enable()


@pytest.mark.parametrize(("status", "expected"), [
    (ScanStatus.CLEAN, True),
    (ScanStatus.INFECTED, True),
    (ScanStatus.ERROR, False),
    (ScanStatus.TIMEOUT, False),
    (ScanStatus.CANCELLED, False),
])
def test_scheduler_only_commits_completed_scan_status(
    tmp_path: Path, status: ScanStatus, expected: bool
) -> None:
    manager = ScheduledScanManager(
        ScanTaskRunner(StubEngine()), SettingsStore(tmp_path / "settings.json")
    )
    result = ScanResult(
        target=str(tmp_path),
        clean=status is ScanStatus.CLEAN,
        status=status,
        error="failure" if status in (ScanStatus.ERROR, ScanStatus.TIMEOUT) else None,
    )
    assert manager._is_successful_daily_result(result) is expected
