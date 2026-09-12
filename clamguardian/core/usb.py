"""USB / removable media auto-scan orchestration."""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from .base import ScanResult, ScanStatus
from .profiles import DEFAULT_PROFILE, ScanProfile
from .runner import ScanTaskRunner

if TYPE_CHECKING:
    from ..history import HistoryStore


class USBScanError(RuntimeError):
    """Raised when a USB device scan operation fails."""


class USBDeviceScanner:
    """Orchestrate removable media and USB drive scanning.

    Reuses existing :class:`~clamguardian.core.runner.ScanTaskRunner` and
    :class:`~clamguardian.engines.clamav.BaseAVEngine`. Prevents duplicate
    simultaneous scans of the same mount target and handles device
    disappearance gracefully during scan execution.
    """

    DEFAULT_MOUNT_ROOTS = (Path("/media"), Path("/run/media"), Path("/mnt"))

    def __init__(
        self,
        runner: ScanTaskRunner,
        *,
        history_store: HistoryStore | None = None,
        default_profile: ScanProfile | None = None,
    ) -> None:
        self.runner = runner
        self.history_store = history_store
        self.profile = default_profile or DEFAULT_PROFILE
        self._active_mounts: set[Path] = set()

    def is_removable_mount(self, mount_point: Path) -> bool:
        """Return whether *mount_point* is located under standard removable mount roots."""
        try:
            resolved = Path(mount_point).expanduser().resolve(strict=False)
            return any(
                resolved == root or root in resolved.parents
                for root in self.DEFAULT_MOUNT_ROOTS
            )
        except OSError:
            return False

    async def scan_device(
        self,
        mount_point: Path,
        *,
        profile: ScanProfile | None = None,
        on_start: Callable[[], None] | None = None,
    ) -> ScanResult:
        """Validate target and submit removable media scan through ScanTaskRunner."""
        target = Path(mount_point).expanduser().resolve()
        if not target.exists():
            return ScanResult(
                target=str(target),
                clean=False,
                status=ScanStatus.ERROR,
                error=f"Device mount point does not exist: {target}",
            )
        if not target.is_dir():
            return ScanResult(
                target=str(target),
                clean=False,
                status=ScanStatus.ERROR,
                error=f"Device target is not a directory: {target}",
            )

        if target in self._active_mounts:
            return ScanResult(
                target=str(target),
                clean=False,
                status=ScanStatus.ERROR,
                error=f"Scan already in progress for mount point: {target}",
            )

        selected_profile = profile or self.profile
        self._active_mounts.add(target)
        try:
            result = await self.runner.submit(
                target, profile=selected_profile, on_start=on_start
            )
            if self.history_store is not None:
                with contextlib.suppress(Exception):
                    await self.history_store.record_scan(result, profile=selected_profile)
            return result
        except asyncio.CancelledError:
            return ScanResult.cancelled(str(target))
        except Exception as exc:
            return ScanResult(
                target=str(target),
                clean=False,
                status=ScanStatus.ERROR,
                error=f"USB scan failed: {exc}",
            )
        finally:
            self._active_mounts.discard(target)
