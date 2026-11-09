"""Tests for scheduled scans and autostart functionality."""

from __future__ import annotations

from datetime import datetime, time
from pathlib import Path

import pytest

from clamguardian.core.autostart import AutostartManager
from clamguardian.core.base import BaseAVEngine, ScanResult
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


@pytest.mark.parametrize("profile", ["public", "premium"])
def test_set_schedule_preserves_intelligence_profile_and_other_settings(
    tmp_path: Path, profile: str
) -> None:
    store = SettingsStore(tmp_path / "settings.json")
    original = AppSettings(
        default_profile_id="balanced",
        notifications_enabled=False,
        color_scheme="dark",
        usb_autoscan_enabled=True,
        intelligence_enabled=True,
        intelligence_profile=profile,
        realtime_enabled=True,
        realtime_paths=("/home/example/Downloads",),
        scheduled_scans_enabled=False,
        scheduled_hour=4,
        scheduled_minute=15,
        autostart_enabled=True,
    )
    store.save(original)
    manager = ScheduledScanManager(ScanTaskRunner(StubEngine()), store)

    manager.set_schedule(True, hour=7, minute=45)

    updated = store.load()
    assert updated.intelligence_profile == profile
    assert updated.intelligence_enabled is True
    assert updated.default_profile_id == "balanced"
    assert updated.notifications_enabled is False
    assert updated.color_scheme == "dark"
    assert updated.usb_autoscan_enabled is True
    assert updated.realtime_enabled is True
    assert updated.realtime_paths == ("/home/example/Downloads",)
    assert updated.autostart_enabled is True
    assert updated.scheduled_scans_enabled is True
    assert (updated.scheduled_hour, updated.scheduled_minute) == (7, 45)
