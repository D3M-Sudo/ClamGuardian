"""User-level scheduled scan execution and missed-scan recovery."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable
from datetime import datetime, time
from pathlib import Path
from typing import TYPE_CHECKING

from .base import ScanResult, ScanStatus
from .profiles import DEFAULT_PROFILE, ScanProfile
from .runner import ScanTaskRunner
from .settings import AppSettings, SettingsStore

if TYPE_CHECKING:
    from ..history import HistoryStore

logger = logging.getLogger(__name__)


class ScheduledScanManager:
    """Manage unprivileged user-level scheduled scans."""

    def __init__(
        self,
        runner: ScanTaskRunner,
        settings_store: SettingsStore,
        *,
        history_store: HistoryStore | None = None,
        default_target: Path | None = None,
        default_profile: ScanProfile | None = None,
        on_scan_complete: Callable[[ScanResult], None] | None = None,
    ) -> None:
        self.runner = runner
        self.settings_store = settings_store
        self.history_store = history_store
        self.target = default_target or Path.home()
        self.profile = default_profile or DEFAULT_PROFILE
        self.on_scan_complete = on_scan_complete
        self._task: asyncio.Task[None] | None = None
        self._running = False
        self._last_run_date: str | None = self._load_last_run_date()

    def _last_run_path(self) -> Path:
        return self.settings_store.path.with_name("scheduled-last-run")

    def _load_last_run_date(self) -> str | None:
        try:
            value = self._last_run_path().read_text(encoding="ascii").strip()
        except OSError:
            return None
        return value if len(value) == 10 else None

    @staticmethod
    def _is_successful_daily_result(result: ScanResult) -> bool:
        """Only clean or infected terminal scans count as completed daily work."""
        return result.status in (ScanStatus.CLEAN, ScanStatus.INFECTED)

    def _save_last_run_date(self, value: str) -> None:
        path = self._last_run_path()
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.tmp")
        temporary.write_text(value + "\n", encoding="ascii")
        temporary.replace(path)
        self._last_run_date = value

    @property
    def is_running(self) -> bool:
        """Return whether scheduler loop is active."""
        return self._running

    def is_enabled(self) -> bool:
        """Return whether scheduled scans are enabled in settings."""
        return self.settings_store.load().scheduled_scans_enabled

    def get_schedule_time(self) -> time:
        """Return scheduled daily time (hour, minute)."""
        settings = self.settings_store.load()
        return time(hour=settings.scheduled_hour, minute=settings.scheduled_minute)

    def set_schedule(self, enabled: bool, hour: int = 2, minute: int = 0) -> None:
        """Update scheduled scan settings."""
        settings = self.settings_store.load()
        updated = AppSettings(
            default_profile_id=settings.default_profile_id,
            notifications_enabled=settings.notifications_enabled,
            color_scheme=settings.color_scheme,
            usb_autoscan_enabled=settings.usb_autoscan_enabled,
            intelligence_enabled=settings.intelligence_enabled,
            realtime_enabled=settings.realtime_enabled,
            realtime_paths=settings.realtime_paths,
            scheduled_scans_enabled=enabled,
            scheduled_hour=hour % 24,
            scheduled_minute=minute % 60,
            autostart_enabled=settings.autostart_enabled,
        )
        self.settings_store.save(updated)

    async def start(self) -> None:
        """Start scheduler task loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._scheduler_loop())

    async def stop(self) -> None:
        """Stop scheduler task loop."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    async def trigger_now(self) -> ScanResult:
        """Manually trigger scheduled scan immediately."""
        result = await self.runner.submit(self.target, profile=self.profile)
        if self.history_store is not None:
            with contextlib.suppress(Exception):
                await self.history_store.record_scan(result, profile=self.profile)
        if self.on_scan_complete is not None:
            with contextlib.suppress(Exception):
                self.on_scan_complete(result)
        return result

    async def _scheduler_loop(self) -> None:
        while self._running:
            try:
                if self.is_enabled():
                    now = datetime.now()
                    sched_time = self.get_schedule_time()
                    today_str = now.strftime("%Y-%m-%d")

                    # Check if today's scheduled time has passed and today's scan hasn't run yet
                    if now.time() >= sched_time and self._last_run_date != today_str:
                        logger.info("Executing scheduled daily scan on %s", self.target)
                        try:
                            result = await self.trigger_now()
                        except Exception as exc:
                            logger.error("Scheduled scan failed: %s", exc)
                        else:
                            if self._is_successful_daily_result(result):
                                self._save_last_run_date(today_str)
                            else:
                                # ERROR, TIMEOUT and CANCELLED are not completed
                                # daily scans; leave the date uncommitted so the
                                # scheduler can retry later and after restart.
                                logger.warning(
                                    "Scheduled scan ended with %s; it will be retried",
                                    result.status.value,
                                )

                await asyncio.sleep(10)
            except asyncio.CancelledError:
                break
            except Exception as err:
                logger.error("Error in scheduled scan loop: %s", err)
                await asyncio.sleep(30)
