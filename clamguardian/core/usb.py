"""USB / removable media auto-scan orchestration and monitoring."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .base import ScanResult, ScanStatus
from .profiles import DEFAULT_PROFILE, ScanProfile
from .runner import ScanTaskRunner

if TYPE_CHECKING:
    from ..history import HistoryStore

logger = logging.getLogger(__name__)


def _is_removable_device_mount(path: Path) -> bool:
    """Fail closed unless the mount resolves to removable/USB block media."""
    try:
        if not path.is_mount():
            return False
        device = os.stat(path).st_dev
        major, minor = os.major(device), os.minor(device)
        device_id = f"{major}:{minor}"
        sys_device = (Path("/sys/dev/block") / device_id).resolve(strict=True)
        for parent in (sys_device, *sys_device.parents):
            removable = parent / "removable"
            if removable.is_file() and removable.read_text(encoding="ascii").strip() == "1":
                return True
        # Some USB bridges report removable=0; udev's persistent database
        # provides a second read-only identification signal.
        udev_record = Path("/run/udev/data") / f"b{device_id}"
        if udev_record.is_file():
            return any(
                line.strip() == "E:ID_BUS=usb"
                for line in udev_record.read_text(encoding="utf-8", errors="replace").splitlines()
            )
    except (OSError, ValueError):
        return False
    return False


class USBScanError(RuntimeError):
    """Raised when a USB device scan operation fails."""


@dataclass(frozen=True, slots=True)
class MountEvent:
    """Represents a mount or unmount event."""

    mount_point: Path
    is_mount: bool


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
        allowed_mount_roots: tuple[Path, ...] | None = None,
        mount_detector: Callable[[Path], bool] | None = None,
    ) -> None:
        self.runner = runner
        self.history_store = history_store
        self.profile = default_profile or DEFAULT_PROFILE
        self.mount_roots = tuple(Path(root).resolve() for root in (allowed_mount_roots or self.DEFAULT_MOUNT_ROOTS))
        self._mount_detector = mount_detector or _is_removable_device_mount
        self._active_mounts: set[Path] = set()
        self._lock = asyncio.Lock()

    def is_removable_mount(self, mount_point: Path) -> bool:
        """Return whether *mount_point* is located strictly under standard removable mount roots."""
        try:
            target = Path(mount_point).expanduser()
            resolved = target.resolve(strict=False)
            under_allowed_root = any(
                resolved != root and root in resolved.parents
                for root in self.mount_roots
            )
            return under_allowed_root and self._mount_detector(resolved)
        except (OSError, ValueError):
            return False

    def validate_target(self, mount_point: Path) -> Path:
        """Validate that mount point is an existing directory under a removable mount root."""
        target = Path(mount_point).expanduser()
        if not target.exists():
            raise USBScanError(f"Device mount point does not exist: {target}")
        if target.is_symlink():
            resolved = target.resolve()
            if not resolved.exists():
                raise USBScanError(f"Symlink target does not exist: {target} -> {resolved}")
            target = resolved
        if not target.is_dir():
            raise USBScanError(f"Device target is not a directory: {target}")
        if not self.is_removable_mount(target):
            raise USBScanError(f"Target is not a valid removable media mount point: {target}")
        return target

    async def scan_device(
        self,
        mount_point: Path,
        *,
        profile: ScanProfile | None = None,
        on_start: Callable[[], None] | None = None,
    ) -> ScanResult:
        """Validate target and submit removable media scan through ScanTaskRunner."""
        try:
            target = self.validate_target(mount_point)
        except USBScanError as exc:
            return ScanResult(
                target=str(mount_point),
                clean=False,
                status=ScanStatus.ERROR,
                error=str(exc),
            )

        async with self._lock:
            if target in self._active_mounts:
                return ScanResult(
                    target=str(target),
                    clean=False,
                    status=ScanStatus.ERROR,
                    error=f"Scan already in progress for mount point: {target}",
                )
            self._active_mounts.add(target)

        selected_profile = profile or self.profile
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
            async with self._lock:
                self._active_mounts.discard(target)

    def is_scanning(self, mount_point: Path) -> bool:
        """Check if *mount_point* is currently being scanned."""
        try:
            target = Path(mount_point).expanduser().resolve()
            return target in self._active_mounts
        except OSError:
            return False


class USBMountMonitor:
    """Monitor system mounts for new removable devices and trigger USBDeviceScanner."""

    def __init__(
        self,
        scanner: USBDeviceScanner,
        *,
        poll_interval: float = 1.0,
        on_mount_scanned: Callable[[ScanResult], None] | None = None,
    ) -> None:
        self.scanner = scanner
        self.poll_interval = poll_interval
        self.on_mount_scanned = on_mount_scanned
        self._known_mounts: set[Path] = set()
        self._task: asyncio.Task[None] | None = None
        self._scan_tasks: dict[Path, asyncio.Task[None]] = {}
        self._running = False

    def get_current_mounts(self) -> set[Path]:
        """Read currently mounted filesystems from /proc/mounts or /etc/mtab."""
        mounts: set[Path] = set()
        proc_mounts = Path("/proc/mounts")
        if not proc_mounts.exists():
            return mounts
        try:
            lines = proc_mounts.read_text(encoding="utf-8", errors="replace").splitlines()
            for line in lines:
                parts = line.split()
                if len(parts) >= 2:
                    mount_field = parts[1]
                    for escaped, decoded in (
                        (r"\040", " "),
                        (r"\011", "\t"),
                        (r"\012", "\n"),
                        (r"\134", "\\"),
                    ):
                        mount_field = mount_field.replace(escaped, decoded)
                    mount_path = Path(mount_field)
                    if self.scanner.is_removable_mount(mount_path):
                        mounts.add(mount_path)
        except OSError as err:
            logger.warning("Failed to read /proc/mounts: %s", err)
        return mounts

    async def start(self) -> None:
        """Start monitoring mount points."""
        if self._running:
            return
        self._running = True
        self._known_mounts = self.get_current_mounts()
        self._task = asyncio.create_task(self._poll_loop())

    async def stop(self) -> None:
        """Stop monitoring mount points."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        scans = list(self._scan_tasks.values())
        for task in scans:
            task.cancel()
        if scans:
            await asyncio.gather(*scans, return_exceptions=True)
        self._scan_tasks.clear()

    async def _poll_loop(self) -> None:
        while self._running:
            try:
                await asyncio.sleep(self.poll_interval)
                current = self.get_current_mounts()
                new_mounts = current - self._known_mounts
                removed_mounts = self._known_mounts - current
                self._known_mounts = current

                # An unmount invalidates the scan target: cancel the runner
                # task rather than continuing against a disappearing device.
                for mount in removed_mounts:
                    task = self._scan_tasks.get(mount)
                    if task is not None:
                        task.cancel()

                for mount in new_mounts:
                    if self._running and not self.scanner.is_scanning(mount):
                        task = asyncio.create_task(self._handle_new_mount(mount))
                        self._scan_tasks[mount] = task
                        task.add_done_callback(
                            lambda done, key=mount: self._scan_tasks.pop(key, None)
                            if self._scan_tasks.get(key) is done else None
                        )
            except asyncio.CancelledError:
                break
            except Exception as err:
                logger.error("Error in USB mount monitor loop: %s", err)

    async def _handle_new_mount(self, mount: Path) -> None:
        try:
            result = await self.scanner.scan_device(mount)
            if self.on_mount_scanned is not None:
                self.on_mount_scanned(result)
        except Exception as err:
            logger.error("Failed to auto-scan mount %s: %s", mount, err)
