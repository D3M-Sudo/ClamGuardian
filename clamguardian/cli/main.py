"""ClamGuardian CLI entry point and command implementations.

Responsibilities of this module (and of the whole :mod:`clamguardian.cli`
package) are strictly limited to:

* argument parsing and usage validation;
* target existence validation (read-only, mirroring the engine's contract);
* resolving profiles through :data:`~clamguardian.core.profiles.DEFAULT_REGISTRY`;
* driving the event loop with a thin synchronous entry point;
* presenting results (human or JSON);
* wiring scan completion into the History recorder (best-effort): the Core
  produces a :class:`ScanResult`, the Controller decides the scan is finished,
  and the Recorder persists it without ever altering the scan's outcome.

Scan orchestration is delegated entirely to the Core:
``ScanProfileRegistry`` → ``ScanTaskRunner`` → ``BaseAVEngine``. The CLI
never spawns subprocesses, never touches clamd, and never builds ClamAV
arguments.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import IO, TYPE_CHECKING

from .. import __version__
from ..core.base import BaseAVEngine, ScanResult
from ..core.diagnostics import CheckResult, critical_missing, run_dependency_checks
from ..core.errors import ClamGuardianError, ProfileError
from ..core.profiles import DEFAULT_PROFILE, DEFAULT_REGISTRY, ScanProfile
from ..core.runner import ScanTaskRunner
from ..engines.clamav import ClamAVEngine
from ..history import (
    HistoryError,
    HistoryRecord,
    HistoryStore,
    SqliteHistoryStore,
    decode_timestamp,
    is_valid_status,
    valid_statuses,
)
from .exit_codes import (
    EXIT_CANCELLED,
    EXIT_DOCTOR_FAILED,
    EXIT_ENGINE_ERROR,
    EXIT_INFECTED,
    EXIT_OK,
    EXIT_TIMEOUT,
    EXIT_USAGE,
)
from .output import (
    cancelled_payload,
    doctor_to_payload,
    format_doctor,
    format_history_list,
    format_history_record,
    format_human,
    format_profiles,
    format_purge_result,
    history_record_to_payload,
    result_to_payload,
)

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Sequence

__all__ = ["build_parser", "main", "run"]


class _Streams:
    """Output streams bundle (stdout/stderr) for testability."""

    def __init__(self, out: IO[str], err: IO[str]) -> None:
        self.out = out
        self.err = err


def _default_engine() -> BaseAVEngine:
    """Return the production engine (kept indirection-friendly for tests)."""
    return ClamAVEngine()


def _default_history_store() -> HistoryStore:
    """Return the production history store.

    A failure to open the store surfaces as :class:`HistoryError`; the scan flow
    treats that as a best-effort disable so an unavailable history layer never
    blocks a completed scan. Kept indirection-friendly for tests, exactly like
    :func:`_default_engine`.
    """
    return SqliteHistoryStore()


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the whole CLI."""
    parser = argparse.ArgumentParser(
        prog="clamguardian",
        description="ClamGuardian — ClamAV security framework command-line interface.",
        epilog=(
            "Exit codes: 0 clean/ok, 1 threats detected, 2 usage error, "
            "3 engine/runtime error, 4 timeout, 5 cancelled (Ctrl+C), "
            "6 diagnostics: critical dependencies missing."
        ),
    )
    parser.add_argument("--version", action="version", version=f"ClamGuardian {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    scan = sub.add_parser(
        "scan",
        help="scan a file or directory",
        description="Scan a file or directory with the ClamAV engine.",
        epilog=(
            "Profiles are resolved from the Core registry "
            "(clamguardian.core.profiles): quick, home, full, custom. "
            "Without --profile the Core default profile is used "
            "(id: 'default', Standard Scan)."
        ),
    )
    scan.add_argument("path", metavar="PATH", help="file or directory to scan")
    scan.add_argument(
        "--profile",
        metavar="PROFILE",
        default=None,
        help="scan profile id from the Core registry (default: core default profile)",
    )
    scan.add_argument(
        "--json",
        action="store_true",
        help="emit a machine-readable JSON report on stdout (diagnostics on stderr)",
    )
    scan.set_defaults(func=_cmd_scan)

    profiles_cmd = sub.add_parser(
        "profiles",
        help="list available scan profiles",
        description="List the scan profiles registered in the Core registry.",
    )
    profiles_cmd.add_argument(
        "--json", action="store_true", help="emit the profile list as JSON on stdout"
    )
    profiles_cmd.set_defaults(func=_cmd_profiles)

    version_cmd = sub.add_parser(
        "version",
        help="print the ClamGuardian version",
        description="Print the ClamGuardian version (single source of truth).",
    )
    version_cmd.set_defaults(func=_cmd_version)

    history = sub.add_parser(
        "history",
        help="query and report scan history",
        description=(
            "Query the scan history recorded by ClamGuardian. "
            "Use `history list` to list recent scans and `history show ID` "
            "to inspect a single record."
        ),
    )
    history_sub = history.add_subparsers(
        dest="history_action", required=True, metavar="ACTION"
    )

    history_list = history_sub.add_parser(
        "list",
        help="list recent scans",
        description="List recent scans from history, newest first.",
    )
    history_list.add_argument(
        "--limit",
        type=int,
        default=20,
        metavar="N",
        help="maximum number of records to show (default: 20)",
    )
    history_list.add_argument(
        "--status",
        default=None,
        metavar="STATUS",
        help="filter by status (clean, infected, error, timeout, cancelled)",
    )
    history_list.add_argument(
        "--json",
        action="store_true",
        help="emit the history page as JSON on stdout",
    )
    history_list.set_defaults(func=_cmd_history_list)

    history_show = history_sub.add_parser(
        "show",
        help="show a single history record",
        description="Show the full details of a single history record by id.",
    )
    history_show.add_argument("scan_id", metavar="ID", help="id of the scan to show")
    history_show.add_argument(
        "--json",
        action="store_true",
        help="emit the record as JSON on stdout",
    )
    history_show.set_defaults(func=_cmd_history_show)

    history_purge = history_sub.add_parser(
        "purge",
        help="delete history records by retention criteria",
        description=(
            "Delete scan history records matching the given criteria. "
            "At least one of --before / --status is required."
        ),
    )
    history_purge.add_argument(
        "--before",
        default=None,
        metavar="TIMESTAMP",
        help="delete records started before this ISO-8601 timestamp (exclusive)",
    )
    history_purge.add_argument(
        "--status",
        default=None,
        metavar="STATUS",
        help="only delete records with this status (clean, infected, error, timeout, cancelled)",
    )
    history_purge.add_argument(
        "--json",
        action="store_true",
        help="emit the purge result as JSON on stdout",
    )
    history_purge.set_defaults(func=_cmd_history_purge)

    doctor_cmd = sub.add_parser(
        "doctor",
        help="check that the system is ready to scan",
        description=(
            "Run the ClamGuardian dependency diagnostics: ClamAV binaries, "
            "clamd daemon, signature databases and execution environment, "
            "with per-distro remedies for anything that needs attention."
        ),
    )
    doctor_cmd.add_argument(
        "--json",
        action="store_true",
        help="emit the diagnostics report as JSON on stdout",
    )
    doctor_cmd.set_defaults(func=_cmd_doctor)

    ui_cmd = sub.add_parser(
        "ui",
        help="launch the GTK4/Libadwaita desktop application",
        description=(
            "Launch the ClamGuardian desktop application. Requires PyGObject "
            "with GTK 4 and Libadwaita (install the 'gtk' extra: "
            "pip install 'clamguardian[gtk]')."
        ),
    )
    ui_cmd.set_defaults(func=_cmd_ui)

    usb_cmd = sub.add_parser(
        "usb",
        help="scan removable media or manage USB auto-scan",
        description="Scan removable media mount points or inspect/configure USB auto-scan.",
    )
    usb_sub = usb_cmd.add_subparsers(dest="usb_action", required=True, metavar="ACTION")

    usb_scan = usb_sub.add_parser(
        "scan",
        help="scan a removable media mount point",
        description="Scan a removable media mount point safely.",
    )
    usb_scan.add_argument("mount_point", metavar="MOUNT", help="removable media mount point")
    usb_scan.add_argument(
        "--profile",
        metavar="PROFILE",
        default=None,
        help="scan profile id from Core registry",
    )
    usb_scan.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON report",
    )
    usb_scan.set_defaults(func=_cmd_usb_scan)

    usb_status = usb_sub.add_parser(
        "status",
        help="show USB auto-scan configuration",
        description="Show whether USB auto-scan is enabled and active mount roots.",
    )
    usb_status.add_argument(
        "--json",
        action="store_true",
        help="emit status as JSON on stdout",
    )
    usb_status.set_defaults(func=_cmd_usb_status)

    usb_enable = usb_sub.add_parser(
        "enable",
        help="enable USB auto-scan setting",
        description="Enable automatic scanning of removable media upon mount.",
    )
    usb_enable.set_defaults(func=_cmd_usb_enable)

    usb_disable = usb_sub.add_parser(
        "disable",
        help="disable USB auto-scan setting",
        description="Disable automatic scanning of removable media.",
    )
    usb_disable.set_defaults(func=_cmd_usb_disable)

    intel_cmd = sub.add_parser(
        "intel",
        help="threat intelligence lookups and configuration",
        description="Query threat intelligence for file hashes or configure VirusTotal.",
    )
    intel_sub = intel_cmd.add_subparsers(dest="intel_action", required=True, metavar="ACTION")

    intel_lookup = intel_sub.add_parser(
        "lookup",
        help="lookup SHA-256 hash in VirusTotal",
        description="Query VirusTotal for a file's SHA-256 digest without uploading the file.",
    )
    intel_lookup.add_argument("hash", metavar="SHA256", help="64-character SHA-256 hash")
    intel_lookup.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON report",
    )
    intel_lookup.set_defaults(func=_cmd_intel_lookup)

    intel_upload = intel_sub.add_parser(
        "upload",
        help="submit a file after hash lookup and explicit per-file consent",
        description="Look up the file SHA-256 first; upload only if absent and the user types UPLOAD.",
    )
    intel_upload.add_argument("path", metavar="PATH")
    intel_upload.set_defaults(func=_cmd_intel_upload)

    intel_set_key = intel_sub.add_parser(
        "set-key",
        help="store the VirusTotal API key in Secret Service",
        description="Read an API key without echo and store it in the OS Secret Service.",
    )
    intel_set_key.add_argument("--profile", choices=("public", "premium"), default="public")
    intel_set_key.set_defaults(func=_cmd_intel_set_key)

    intel_profile = intel_sub.add_parser("profile", help="select Public or Premium API profile")
    intel_profile.add_argument("profile", choices=("public", "premium"))
    intel_profile.set_defaults(func=_cmd_intel_profile)

    intel_status = intel_sub.add_parser(
        "status",
        help="show threat intelligence status",
        description="Check if threat intelligence is enabled and secret storage is available.",
    )
    intel_status.add_argument(
        "--json",
        action="store_true",
        help="emit status as JSON on stdout",
    )
    intel_status.set_defaults(func=_cmd_intel_status)

    intel_enable = intel_sub.add_parser(
        "enable",
        help="enable threat intelligence",
        description="Enable threat intelligence lookups.",
    )
    intel_enable.set_defaults(func=_cmd_intel_enable)

    intel_disable = intel_sub.add_parser(
        "disable",
        help="disable threat intelligence",
        description="Disable threat intelligence lookups.",
    )
    intel_disable.set_defaults(func=_cmd_intel_disable)

    rt_cmd = sub.add_parser(
        "monitor",
        help="realtime filesystem monitoring",
        description="Inspect or control event-driven realtime filesystem monitoring.",
    )
    rt_sub = rt_cmd.add_subparsers(dest="monitor_action", required=True, metavar="ACTION")

    rt_status = rt_sub.add_parser(
        "status",
        help="show realtime monitoring status and paths",
        description="Show whether realtime monitoring is enabled and configured paths.",
    )
    rt_status.add_argument(
        "--json",
        action="store_true",
        help="emit status as JSON on stdout",
    )
    rt_status.set_defaults(func=_cmd_monitor_status)

    rt_enable = rt_sub.add_parser(
        "enable",
        help="enable realtime monitoring setting",
        description="Enable realtime event-driven filesystem monitoring.",
    )
    rt_enable.set_defaults(func=_cmd_monitor_enable)

    rt_disable = rt_sub.add_parser(
        "disable",
        help="disable realtime monitoring setting",
        description="Disable realtime event-driven filesystem monitoring.",
    )
    rt_disable.set_defaults(func=_cmd_monitor_disable)

    rt_add = rt_sub.add_parser(
        "add",
        help="add a directory to monitored paths",
        description="Add a directory to the realtime monitoring paths list.",
    )
    rt_add.add_argument("path", metavar="PATH", help="directory path to monitor")
    rt_add.set_defaults(func=_cmd_monitor_add)

    rt_remove = rt_sub.add_parser(
        "remove",
        help="remove a directory from monitored paths",
        description="Remove a directory from the realtime monitoring paths list.",
    )
    rt_remove.add_argument("path", metavar="PATH", help="directory path to stop monitoring")
    rt_remove.set_defaults(func=_cmd_monitor_remove)

    sched_cmd = sub.add_parser(
        "schedule",
        help="manage scheduled scan configuration",
        description="Inspect or configure unprivileged daily scheduled scans.",
    )
    sched_sub = sched_cmd.add_subparsers(dest="sched_action", required=True, metavar="ACTION")

    sched_status = sched_sub.add_parser(
        "status",
        help="show scheduled scan settings",
        description="Show whether daily scheduled scans are enabled and scheduled time.",
    )
    sched_status.add_argument(
        "--json",
        action="store_true",
        help="emit status as JSON on stdout",
    )
    sched_status.set_defaults(func=_cmd_sched_status)

    sched_enable = sched_sub.add_parser(
        "enable",
        help="enable daily scheduled scans",
        description="Enable daily scheduled scans with optional --time HH:MM.",
    )
    sched_enable.add_argument(
        "--time",
        metavar="HH:MM",
        default="02:00",
        help="daily scan time in 24h format (default: 02:00)",
    )
    sched_enable.set_defaults(func=_cmd_sched_enable)

    sched_disable = sched_sub.add_parser(
        "disable",
        help="disable daily scheduled scans",
        description="Disable daily scheduled scans.",
    )
    sched_disable.set_defaults(func=_cmd_sched_disable)

    autostart_cmd = sub.add_parser(
        "autostart",
        help="manage user-session autostart",
        description="Enable, disable, or inspect desktop user-session autostart.",
    )
    autostart_sub = autostart_cmd.add_subparsers(
        dest="autostart_action", required=True, metavar="ACTION"
    )

    auto_status = autostart_sub.add_parser(
        "status",
        help="show autostart status",
        description="Show whether desktop user-session autostart is enabled.",
    )
    auto_status.add_argument(
        "--json",
        action="store_true",
        help="emit status as JSON on stdout",
    )
    auto_status.set_defaults(func=_cmd_autostart_status)

    auto_enable = autostart_sub.add_parser(
        "enable",
        help="enable user-session autostart",
        description="Install autostart desktop entry into ~/.config/autostart.",
    )
    auto_enable.set_defaults(func=_cmd_autostart_enable)

    auto_disable = autostart_sub.add_parser(
        "disable",
        help="disable user-session autostart",
        description="Remove autostart desktop entry from ~/.config/autostart.",
    )
    auto_disable.set_defaults(func=_cmd_autostart_disable)

    return parser


def _cmd_version(args: argparse.Namespace, streams: _Streams) -> int:
    del args
    print(f"ClamGuardian {__version__}", file=streams.out)
    return EXIT_OK


def _cmd_doctor(args: argparse.Namespace, streams: _Streams) -> int:
    """Run the Core dependency diagnostics and report readiness to scan."""
    results: list[CheckResult] = run_dependency_checks()
    if args.json:
        print(json.dumps(doctor_to_payload(results)), file=streams.out)
    else:
        print(format_doctor(results), file=streams.out)
    # Exit 6 only for *critical* gaps (clamscan / signature databases):
    # warnings (daemon stopped, stale databases) are reported but never
    # block scripting workflows.
    return EXIT_DOCTOR_FAILED if critical_missing(results) else EXIT_OK


def _cmd_ui(args: argparse.Namespace, streams: _Streams) -> int:
    """Launch the GTK4/Libadwaita desktop application (lazy import)."""
    del args
    from ..ui import GTK_AVAILABLE

    if not GTK_AVAILABLE:
        print(
            "error: GTK 4 / Libadwaita is not available; install PyGObject "
            "with the 'gtk' extra (pip install 'clamguardian[gtk]') or your "
            "distribution's gir1.2-gtk-4.0 / gir1.2-adw-1 packages",
            file=streams.err,
        )
        return EXIT_ENGINE_ERROR
    from ..ui.app import run_ui

    return EXIT_OK if run_ui() == 0 else EXIT_ENGINE_ERROR


def _cmd_usb_status(args: argparse.Namespace, streams: _Streams) -> int:
    from ..core.settings import SettingsStore
    from ..core.usb import USBDeviceScanner

    store = SettingsStore()
    settings = store.load()
    mount_roots = [str(r) for r in USBDeviceScanner.DEFAULT_MOUNT_ROOTS]
    if args.json:
        payload = {
            "usb_autoscan_enabled": settings.usb_autoscan_enabled,
            "allowed_mount_roots": mount_roots,
        }
        print(json.dumps(payload, indent=2), file=streams.out)
    else:
        status_str = "enabled" if settings.usb_autoscan_enabled else "disabled"
        print(f"USB Auto-Scan: {status_str}", file=streams.out)
        print(f"Allowed mount roots: {', '.join(mount_roots)}", file=streams.out)
    return EXIT_OK


def _cmd_usb_enable(args: argparse.Namespace, streams: _Streams) -> int:
    del args
    from ..core.settings import AppSettings, SettingsStore

    store = SettingsStore()
    settings = store.load()
    updated = AppSettings(
        default_profile_id=settings.default_profile_id,
        notifications_enabled=settings.notifications_enabled,
        color_scheme=settings.color_scheme,
        usb_autoscan_enabled=True,
        intelligence_enabled=settings.intelligence_enabled,
        intelligence_profile=settings.intelligence_profile,
        realtime_enabled=settings.realtime_enabled,
        realtime_paths=settings.realtime_paths,
        scheduled_scans_enabled=settings.scheduled_scans_enabled,
        scheduled_hour=settings.scheduled_hour,
        scheduled_minute=settings.scheduled_minute,
        autostart_enabled=settings.autostart_enabled,
    )
    store.save(updated)
    print("USB Auto-Scan enabled", file=streams.out)
    return EXIT_OK


def _cmd_usb_disable(args: argparse.Namespace, streams: _Streams) -> int:
    del args
    from ..core.settings import AppSettings, SettingsStore

    store = SettingsStore()
    settings = store.load()
    updated = AppSettings(
        default_profile_id=settings.default_profile_id,
        notifications_enabled=settings.notifications_enabled,
        color_scheme=settings.color_scheme,
        usb_autoscan_enabled=False,
        intelligence_enabled=settings.intelligence_enabled,
        intelligence_profile=settings.intelligence_profile,
        realtime_enabled=settings.realtime_enabled,
        realtime_paths=settings.realtime_paths,
        scheduled_scans_enabled=settings.scheduled_scans_enabled,
        scheduled_hour=settings.scheduled_hour,
        scheduled_minute=settings.scheduled_minute,
        autostart_enabled=settings.autostart_enabled,
    )
    store.save(updated)
    print("USB Auto-Scan disabled", file=streams.out)
    return EXIT_OK


def _cmd_monitor_status(args: argparse.Namespace, streams: _Streams) -> int:
    from ..core.settings import SettingsStore

    store = SettingsStore()
    settings = store.load()

    if args.json:
        payload = {
            "realtime_enabled": settings.realtime_enabled,
            "monitored_paths": list(settings.realtime_paths),
        }
        print(json.dumps(payload, indent=2), file=streams.out)
    else:
        status_str = "enabled" if settings.realtime_enabled else "disabled"
        print(f"Realtime Monitoring: {status_str}", file=streams.out)
        paths_str = ", ".join(settings.realtime_paths) if settings.realtime_paths else "(none)"
        print(f"Monitored paths: {paths_str}", file=streams.out)
    return EXIT_OK


def _cmd_monitor_enable(args: argparse.Namespace, streams: _Streams) -> int:
    del args
    from ..core.settings import AppSettings, SettingsStore

    store = SettingsStore()
    settings = store.load()
    updated = AppSettings(
        default_profile_id=settings.default_profile_id,
        notifications_enabled=settings.notifications_enabled,
        color_scheme=settings.color_scheme,
        usb_autoscan_enabled=settings.usb_autoscan_enabled,
        intelligence_enabled=settings.intelligence_enabled,
        intelligence_profile=settings.intelligence_profile,
        realtime_enabled=True,
        realtime_paths=settings.realtime_paths,
        scheduled_scans_enabled=settings.scheduled_scans_enabled,
        scheduled_hour=settings.scheduled_hour,
        scheduled_minute=settings.scheduled_minute,
        autostart_enabled=settings.autostart_enabled,
    )
    store.save(updated)
    print("Realtime monitoring enabled", file=streams.out)
    return EXIT_OK


def _cmd_monitor_disable(args: argparse.Namespace, streams: _Streams) -> int:
    del args
    from ..core.settings import AppSettings, SettingsStore

    store = SettingsStore()
    settings = store.load()
    updated = AppSettings(
        default_profile_id=settings.default_profile_id,
        notifications_enabled=settings.notifications_enabled,
        color_scheme=settings.color_scheme,
        usb_autoscan_enabled=settings.usb_autoscan_enabled,
        intelligence_enabled=settings.intelligence_enabled,
        intelligence_profile=settings.intelligence_profile,
        realtime_enabled=False,
        realtime_paths=settings.realtime_paths,
        scheduled_scans_enabled=settings.scheduled_scans_enabled,
        scheduled_hour=settings.scheduled_hour,
        scheduled_minute=settings.scheduled_minute,
        autostart_enabled=settings.autostart_enabled,
    )
    store.save(updated)
    print("Realtime monitoring disabled", file=streams.out)
    return EXIT_OK


def _cmd_monitor_add(args: argparse.Namespace, streams: _Streams) -> int:
    from ..core.settings import AppSettings, SettingsStore

    path = Path(args.path).expanduser().resolve()
    if not path.exists() or not path.is_dir():
        print(f"error: monitored path must be an existing directory: {path}", file=streams.err)
        return EXIT_USAGE

    store = SettingsStore()
    settings = store.load()
    current = list(settings.realtime_paths)
    path_str = str(path)
    if path_str not in current:
        current.append(path_str)

    updated = AppSettings(
        default_profile_id=settings.default_profile_id,
        notifications_enabled=settings.notifications_enabled,
        color_scheme=settings.color_scheme,
        usb_autoscan_enabled=settings.usb_autoscan_enabled,
        intelligence_enabled=settings.intelligence_enabled,
        intelligence_profile=settings.intelligence_profile,
        realtime_enabled=settings.realtime_enabled,
        realtime_paths=tuple(current),
        scheduled_scans_enabled=settings.scheduled_scans_enabled,
        scheduled_hour=settings.scheduled_hour,
        scheduled_minute=settings.scheduled_minute,
        autostart_enabled=settings.autostart_enabled,
    )
    store.save(updated)
    print(f"Added to monitored paths: {path_str}", file=streams.out)
    return EXIT_OK


def _cmd_sched_status(args: argparse.Namespace, streams: _Streams) -> int:
    from ..core.settings import SettingsStore

    store = SettingsStore()
    settings = store.load()
    time_str = f"{settings.scheduled_hour:02d}:{settings.scheduled_minute:02d}"

    if args.json:
        payload = {
            "scheduled_scans_enabled": settings.scheduled_scans_enabled,
            "scheduled_time": time_str,
        }
        print(json.dumps(payload, indent=2), file=streams.out)
    else:
        status_str = "enabled" if settings.scheduled_scans_enabled else "disabled"
        print(f"Daily Scheduled Scans: {status_str}", file=streams.out)
        print(f"Scheduled Time: {time_str}", file=streams.out)
    return EXIT_OK


def _cmd_sched_enable(args: argparse.Namespace, streams: _Streams) -> int:
    from ..core.settings import AppSettings, SettingsStore

    time_raw = args.time.strip()
    try:
        parts = time_raw.split(":")
        hour = int(parts[0])
        minute = int(parts[1]) if len(parts) > 1 else 0
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            raise ValueError
    except Exception:
        print(f"error: invalid time format: {time_raw} (expected HH:MM)", file=streams.err)
        return EXIT_USAGE

    store = SettingsStore()
    settings = store.load()
    updated = AppSettings(
        default_profile_id=settings.default_profile_id,
        notifications_enabled=settings.notifications_enabled,
        color_scheme=settings.color_scheme,
        usb_autoscan_enabled=settings.usb_autoscan_enabled,
        intelligence_enabled=settings.intelligence_enabled,
        intelligence_profile=settings.intelligence_profile,
        realtime_enabled=settings.realtime_enabled,
        realtime_paths=settings.realtime_paths,
        scheduled_scans_enabled=True,
        scheduled_hour=hour,
        scheduled_minute=minute,
        autostart_enabled=settings.autostart_enabled,
    )
    store.save(updated)
    print(f"Daily scheduled scan enabled for {hour:02d}:{minute:02d}", file=streams.out)
    return EXIT_OK


def _cmd_sched_disable(args: argparse.Namespace, streams: _Streams) -> int:
    del args
    from ..core.settings import AppSettings, SettingsStore

    store = SettingsStore()
    settings = store.load()
    updated = AppSettings(
        default_profile_id=settings.default_profile_id,
        notifications_enabled=settings.notifications_enabled,
        color_scheme=settings.color_scheme,
        usb_autoscan_enabled=settings.usb_autoscan_enabled,
        intelligence_enabled=settings.intelligence_enabled,
        intelligence_profile=settings.intelligence_profile,
        realtime_enabled=settings.realtime_enabled,
        realtime_paths=settings.realtime_paths,
        scheduled_scans_enabled=False,
        scheduled_hour=settings.scheduled_hour,
        scheduled_minute=settings.scheduled_minute,
        autostart_enabled=settings.autostart_enabled,
    )
    store.save(updated)
    print("Daily scheduled scans disabled", file=streams.out)
    return EXIT_OK


def _cmd_autostart_status(args: argparse.Namespace, streams: _Streams) -> int:
    from ..core.autostart import AutostartManager

    manager = AutostartManager()
    is_on = manager.is_enabled()
    if args.json:
        print(json.dumps({"autostart_enabled": is_on}, indent=2), file=streams.out)
    else:
        status_str = "enabled" if is_on else "disabled"
        print(f"Autostart at Login: {status_str}", file=streams.out)
    return EXIT_OK


def _cmd_autostart_enable(args: argparse.Namespace, streams: _Streams) -> int:
    del args
    from ..core.autostart import AutostartManager
    from ..core.settings import AppSettings, SettingsStore

    manager = AutostartManager()
    try:
        manager.enable()
    except (OSError, RuntimeError) as exc:
        print(f"error: cannot enable host autostart: {exc}", file=streams.err)
        return EXIT_ENGINE_ERROR

    store = SettingsStore()
    settings = store.load()
    updated = AppSettings(
        default_profile_id=settings.default_profile_id,
        notifications_enabled=settings.notifications_enabled,
        color_scheme=settings.color_scheme,
        usb_autoscan_enabled=settings.usb_autoscan_enabled,
        intelligence_enabled=settings.intelligence_enabled,
        intelligence_profile=settings.intelligence_profile,
        realtime_enabled=settings.realtime_enabled,
        realtime_paths=settings.realtime_paths,
        scheduled_scans_enabled=settings.scheduled_scans_enabled,
        scheduled_hour=settings.scheduled_hour,
        scheduled_minute=settings.scheduled_minute,
        autostart_enabled=True,
    )
    store.save(updated)
    print("Autostart at login enabled", file=streams.out)
    return EXIT_OK


def _cmd_autostart_disable(args: argparse.Namespace, streams: _Streams) -> int:
    del args
    from ..core.autostart import AutostartManager
    from ..core.settings import AppSettings, SettingsStore

    manager = AutostartManager()
    manager.disable()

    store = SettingsStore()
    settings = store.load()
    updated = AppSettings(
        default_profile_id=settings.default_profile_id,
        notifications_enabled=settings.notifications_enabled,
        color_scheme=settings.color_scheme,
        usb_autoscan_enabled=settings.usb_autoscan_enabled,
        intelligence_enabled=settings.intelligence_enabled,
        intelligence_profile=settings.intelligence_profile,
        realtime_enabled=settings.realtime_enabled,
        realtime_paths=settings.realtime_paths,
        scheduled_scans_enabled=settings.scheduled_scans_enabled,
        scheduled_hour=settings.scheduled_hour,
        scheduled_minute=settings.scheduled_minute,
        autostart_enabled=False,
    )
    store.save(updated)
    print("Autostart at login disabled", file=streams.out)
    return EXIT_OK


def _cmd_monitor_remove(args: argparse.Namespace, streams: _Streams) -> int:
    from ..core.settings import AppSettings, SettingsStore

    path = Path(args.path).expanduser().resolve()
    path_str = str(path)

    store = SettingsStore()
    settings = store.load()
    current = [p for p in settings.realtime_paths if p != path_str]

    updated = AppSettings(
        default_profile_id=settings.default_profile_id,
        notifications_enabled=settings.notifications_enabled,
        color_scheme=settings.color_scheme,
        usb_autoscan_enabled=settings.usb_autoscan_enabled,
        intelligence_enabled=settings.intelligence_enabled,
        intelligence_profile=settings.intelligence_profile,
        realtime_enabled=settings.realtime_enabled,
        realtime_paths=tuple(current),
        scheduled_scans_enabled=settings.scheduled_scans_enabled,
        scheduled_hour=settings.scheduled_hour,
        scheduled_minute=settings.scheduled_minute,
        autostart_enabled=settings.autostart_enabled,
    )
    store.save(updated)
    print(f"Removed from monitored paths: {path_str}", file=streams.out)
    return EXIT_OK


def _cmd_intel_set_key(args: argparse.Namespace, streams: _Streams) -> int:
    import getpass

    from ..intelligence.secrets import IntelligenceSecretStore, SecretStorageError

    try:
        api_key = getpass.getpass("VirusTotal API key (input hidden): ")
        IntelligenceSecretStore().set_credential(args.profile, api_key)
    except (SecretStorageError, ValueError) as exc:
        print(f"error: could not store VirusTotal API key: {exc}", file=streams.err)
        return EXIT_ENGINE_ERROR
    print(f"VirusTotal {args.profile} credential stored in OS Secret Service", file=streams.out)
    return EXIT_OK


def _cmd_intel_profile(args: argparse.Namespace, streams: _Streams) -> int:
    from ..core.settings import AppSettings, SettingsStore

    store = SettingsStore()
    settings = store.load()
    updated = AppSettings(
        default_profile_id=settings.default_profile_id,
        notifications_enabled=settings.notifications_enabled,
        color_scheme=settings.color_scheme,
        usb_autoscan_enabled=settings.usb_autoscan_enabled,
        intelligence_enabled=settings.intelligence_enabled,
        intelligence_profile=args.profile,
        realtime_enabled=settings.realtime_enabled,
        realtime_paths=settings.realtime_paths,
        scheduled_scans_enabled=settings.scheduled_scans_enabled,
        scheduled_hour=settings.scheduled_hour,
        scheduled_minute=settings.scheduled_minute,
        autostart_enabled=settings.autostart_enabled,
    )
    store.save(updated)
    print(f"VirusTotal API profile set to {args.profile}", file=streams.out)
    return EXIT_OK


def _cmd_intel_status(args: argparse.Namespace, streams: _Streams) -> int:
    from ..core.settings import SettingsStore
    from ..intelligence.secrets import IntelligenceSecretStore
    from ..intelligence.virustotal import VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED

    settings = SettingsStore().load()
    secret_store = IntelligenceSecretStore()
    secret_avail = secret_store.is_available()
    credentials = {"public": False, "premium": False}
    if secret_avail:
        for profile in credentials:
            try:
                credentials[profile] = bool(secret_store.get_credential(profile))
            except Exception:
                credentials[profile] = False

    if args.json:
        payload = {
            "intelligence_enabled": settings.intelligence_enabled,
            "selected_profile": settings.intelligence_profile,
            "secret_service_available": secret_avail,
            "api_credentials_configured": credentials,
            "public_api_eligible": VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED,
        }
        print(json.dumps(payload, indent=2), file=streams.out)
    else:
        status_str = "enabled" if settings.intelligence_enabled else "disabled"
        print(f"Threat Intelligence: {status_str}", file=streams.out)
        print(f"Selected API Profile: {settings.intelligence_profile}", file=streams.out)
        print(f"Secret Service Available: {secret_avail}", file=streams.out)
        print(f"Public Credential Configured: {credentials['public']}", file=streams.out)
        print(f"Premium Credential Configured: {credentials['premium']}", file=streams.out)
        gate_status = "cleared" if VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED else "BLOCKED — written authorization required"
        print(f"VirusTotal Public API eligibility gate: {gate_status}", file=streams.out)
    return EXIT_OK


def _cmd_intel_enable(args: argparse.Namespace, streams: _Streams) -> int:
    del args
    from ..core.settings import AppSettings, SettingsStore

    store = SettingsStore()
    settings = store.load()
    updated = AppSettings(
        default_profile_id=settings.default_profile_id,
        notifications_enabled=settings.notifications_enabled,
        color_scheme=settings.color_scheme,
        usb_autoscan_enabled=settings.usb_autoscan_enabled,
        intelligence_enabled=True,
        intelligence_profile=settings.intelligence_profile,
        realtime_enabled=settings.realtime_enabled,
        realtime_paths=settings.realtime_paths,
        scheduled_scans_enabled=settings.scheduled_scans_enabled,
        scheduled_hour=settings.scheduled_hour,
        scheduled_minute=settings.scheduled_minute,
        autostart_enabled=settings.autostart_enabled,
    )
    store.save(updated)
    print("Threat Intelligence preference enabled", file=streams.out)
    print(
        "Public API lookups remain blocked until written VirusTotal eligibility "
        "authorization is recorded. Premium requires a valid Premium entitlement.",
        file=streams.out,
    )
    return EXIT_OK


def _cmd_intel_disable(args: argparse.Namespace, streams: _Streams) -> int:
    del args
    from ..core.settings import AppSettings, SettingsStore

    store = SettingsStore()
    settings = store.load()
    updated = AppSettings(
        default_profile_id=settings.default_profile_id,
        notifications_enabled=settings.notifications_enabled,
        color_scheme=settings.color_scheme,
        usb_autoscan_enabled=settings.usb_autoscan_enabled,
        intelligence_enabled=False,
        intelligence_profile=settings.intelligence_profile,
        realtime_enabled=settings.realtime_enabled,
        realtime_paths=settings.realtime_paths,
        scheduled_scans_enabled=settings.scheduled_scans_enabled,
        scheduled_hour=settings.scheduled_hour,
        scheduled_minute=settings.scheduled_minute,
        autostart_enabled=settings.autostart_enabled,
    )
    store.save(updated)
    print("Threat Intelligence disabled", file=streams.out)
    return EXIT_OK


def _cmd_intel_upload(args: argparse.Namespace, streams: _Streams) -> int:
    from ..intelligence.service import ThreatIntelligenceService

    service = ThreatIntelligenceService()
    try:
        preview = service.preview_file_upload(Path(args.path))
        print(f"File: {preview.filename}", file=streams.out)
        print(f"Size: {preview.size} bytes", file=streams.out)
        print(f"SHA-256: {preview.sha256}", file=streams.out)
        lookup = asyncio.run(service.lookup_upload_candidate(preview))
        if lookup.get("found") is True:
            print("VirusTotal already has a report for this hash; upload skipped.", file=streams.out)
            print(json.dumps(lookup, indent=2), file=streams.out)
            return EXIT_OK
        if lookup.get("found") is not False:
            print("error: hash lookup did not establish that the file is absent; upload blocked", file=streams.err)
            return EXIT_ENGINE_ERROR
        print(preview.warning, file=streams.out)
        print("This action transmits the complete file to VirusTotal.", file=streams.out)
        try:
            confirmation = input("Type UPLOAD to consent to this file submission: ")
        except (EOFError, KeyboardInterrupt):
            confirmation = ""
        if confirmation != "UPLOAD":
            print("Upload cancelled; no file contents were transmitted.", file=streams.out)
            return EXIT_CANCELLED
        report = asyncio.run(
            service.upload_file(preview, consent=True, lookup_report=lookup)
        )
    except Exception as exc:
        print(f"error: VirusTotal upload workflow failed ({type(exc).__name__})", file=streams.err)
        return EXIT_ENGINE_ERROR
    print(json.dumps(report, indent=2), file=streams.out)
    return EXIT_OK


def _cmd_intel_lookup(args: argparse.Namespace, streams: _Streams) -> int:
    from ..core.settings import SettingsStore
    from ..intelligence.secrets import IntelligenceSecretStore, SecretStorageError
    from ..intelligence.virustotal import (
        VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED,
        VirusTotalProvider,
    )

    settings = SettingsStore().load()
    if not settings.intelligence_enabled:
        print(
            "error: Threat Intelligence is disabled; run "
            "'clamguardian intel enable' first",
            file=streams.err,
        )
        return EXIT_USAGE
    profile = settings.intelligence_profile
    if profile == "public" and not VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED:
        print(
            "error: VirusTotal lookups are administratively blocked pending review "
            "of applicable Public API terms and product eligibility",
            file=streams.err,
        )
        return EXIT_ENGINE_ERROR

    sha256 = args.hash.strip().lower()
    if len(sha256) != 64 or any(ch not in "0123456789abcdef" for ch in sha256):
        print(
            "error: argument must be a 64-character hexadecimal SHA-256 digest",
            file=streams.err,
        )
        return EXIT_USAGE

    secret_store = IntelligenceSecretStore()
    try:
        api_key = secret_store.get_credential(profile)
    except SecretStorageError as exc:
        print(f"error: {exc}", file=streams.err)
        return EXIT_ENGINE_ERROR

    if not api_key:
        print("error: no VirusTotal API key configured in Secret Service", file=streams.err)
        return EXIT_ENGINE_ERROR

    provider = VirusTotalProvider(api_key, profile=profile)
    try:
        result = asyncio.run(provider.lookup_hash(sha256))
    except Exception as exc:
        print(f"error: lookup failed: {exc}", file=streams.err)
        return EXIT_ENGINE_ERROR

    if args.json:
        print(json.dumps(result, indent=2), file=streams.out)
    else:
        found = result.get("found", False)
        print(f"Hash: {sha256}", file=streams.out)
        print(f"Found: {found}", file=streams.out)
        if found:
            malicious = result.get("malicious", False)
            print(f"Malicious verdict: {malicious}", file=streams.out)
            stats = result.get("last_analysis_stats", {})
            total = sum(stats.values())
            mal_count = stats.get("malicious", 0)
            print(f"Detections: {mal_count} / {total}", file=streams.out)
            print(f"Permalink: {result.get('permalink')}", file=streams.out)
    return EXIT_OK


def _cmd_usb_scan(args: argparse.Namespace, streams: _Streams) -> int:
    from ..core.usb import USBDeviceScanner

    profile = _resolve_profile(args.profile, streams)
    if profile is None:
        return EXIT_USAGE
    mount_path = Path(args.mount_point)

    engine = _default_engine()
    runner = ScanTaskRunner(engine, max_concurrency=1)
    history_store: HistoryStore | None = None
    try:
        history_store = _default_history_store()
    except HistoryError as exc:
        print(f"warning: history recording disabled: {exc}", file=streams.err)

    scanner = USBDeviceScanner(runner, history_store=history_store, default_profile=profile)
    if not args.json:
        print(f"ClamGuardian USB Scan\nMount: {mount_path}", file=streams.out)
        print("Scanning removable device...", file=streams.out)

    try:
        result = asyncio.run(scanner.scan_device(mount_path, profile=profile))
    except KeyboardInterrupt:
        print("Scan cancelled by user", file=streams.err)
        return EXIT_CANCELLED
    except Exception as exc:
        print(f"error: USB scan failed: {exc}", file=streams.err)
        return EXIT_ENGINE_ERROR
    finally:
        if history_store is not None:
            with contextlib.suppress(Exception):
                asyncio.run(history_store.close())

    return _report_result(result, profile.id, args, streams)


async def _history_list(
    store: HistoryStore, args: argparse.Namespace
) -> list[HistoryRecord]:
    """Fetch a page of history records honoring the CLI filters."""
    return await store.list_scans(status=args.status, limit=args.limit)


async def _history_show(
    store: HistoryStore, args: argparse.Namespace
) -> HistoryRecord | None:
    """Fetch a single history record by id."""
    return await store.get_scan(args.scan_id)


def _open_history_store(streams: _Streams) -> HistoryStore | None:
    """Open the history store, reporting a clear error on failure.

    Unlike recording during a scan, an unavailable history store *blocks* the
    `history` command: there is nothing to report without it. The failure is
    surfaced as a usage/runtime error rather than silently ignored.
    """
    try:
        return _default_history_store()
    except HistoryError as exc:
        print(f"error: cannot open history store: {exc}", file=streams.err)
        return None


def _check_history_status(status: str | None, streams: _Streams) -> bool:
    """Validate an optional ``--status`` filter against the persisted states."""
    if status is not None and not is_valid_status(status):
        print(
            f"error: unknown status: {status!r} "
            f"(expected one of: {', '.join(valid_statuses())})",
            file=streams.err,
        )
        return False
    return True


def _cmd_history_list(args: argparse.Namespace, streams: _Streams) -> int:
    if not _check_history_status(args.status, streams):
        return EXIT_USAGE
    if args.limit is not None and args.limit <= 0:
        print("error: --limit must be a positive integer", file=streams.err)
        return EXIT_USAGE
    store = _open_history_store(streams)
    if store is None:
        return EXIT_ENGINE_ERROR
    try:
        records = asyncio.run(_history_list(store, args))
    except HistoryError as exc:
        print(f"error: cannot read history: {exc}", file=streams.err)
        return EXIT_ENGINE_ERROR
    finally:
        with contextlib.suppress(Exception):
            asyncio.run(store.close())
    if args.json:
        payload = {
            "count": len(records),
            "records": [history_record_to_payload(r) for r in records],
        }
        print(json.dumps(payload, indent=2), file=streams.out)
    else:
        print(format_history_list(records), file=streams.out)
    return EXIT_OK


def _cmd_history_show(args: argparse.Namespace, streams: _Streams) -> int:
    store = _open_history_store(streams)
    if store is None:
        return EXIT_ENGINE_ERROR
    try:
        record = asyncio.run(_history_show(store, args))
    except HistoryError as exc:
        print(f"error: cannot read history: {exc}", file=streams.err)
        return EXIT_ENGINE_ERROR
    finally:
        with contextlib.suppress(Exception):
            asyncio.run(store.close())
    if record is None:
        print(f"error: scan not found: {args.scan_id}", file=streams.err)
        return EXIT_USAGE
    if args.json:
        print(json.dumps(history_record_to_payload(record), indent=2), file=streams.out)
    else:
        print(format_history_record(record), file=streams.out)
    return EXIT_OK


async def _history_purge(
    store: HistoryStore,
    before: datetime | None,
    status: str | None,
) -> int:
    """Purge history records matching the criteria; return the deleted count."""
    return await store.purge(before=before, status=status)


def _cmd_history_purge(args: argparse.Namespace, streams: _Streams) -> int:
    before = _parse_history_timestamp(args.before, streams)
    if args.before is not None and before is None:
        return EXIT_USAGE
    if not _check_history_status(args.status, streams):
        return EXIT_USAGE
    if before is None and args.status is None:
        print(
            "error: purge requires at least one of --before / --status",
            file=streams.err,
        )
        return EXIT_USAGE
    store = _open_history_store(streams)
    if store is None:
        return EXIT_ENGINE_ERROR
    try:
        deleted = asyncio.run(_history_purge(store, before, args.status))
    except HistoryError as exc:
        print(f"error: cannot purge history: {exc}", file=streams.err)
        return EXIT_ENGINE_ERROR
    finally:
        with contextlib.suppress(Exception):
            asyncio.run(store.close())
    if args.json:
        print(json.dumps({"deleted": deleted}, indent=2), file=streams.out)
    else:
        print(format_purge_result(deleted), file=streams.out)
    return EXIT_OK


def _parse_history_timestamp(raw: str | None, streams: _Streams) -> datetime | None:
    """Parse an ISO-8601 timestamp for history commands; ``None`` if *raw* is ``None``."""
    if raw is None:
        return None
    try:
        return decode_timestamp(raw)
    except ValueError:
        print(f"error: invalid timestamp: {raw!r}", file=streams.err)
        return None


def _cmd_profiles(args: argparse.Namespace, streams: _Streams) -> int:
    profiles = DEFAULT_REGISTRY.list()
    if args.json:
        payload = [
            {"id": profile.id, "name": profile.name, "description": profile.description}
            for profile in profiles
        ]
        print(json.dumps(payload, indent=2), file=streams.out)
    else:
        print(format_profiles(profiles), file=streams.out)
    return EXIT_OK


def _resolve_profile(profile_id: str | None, streams: _Streams) -> ScanProfile | None:
    """Resolve the profile via the Core registry; report errors on stderr."""
    if profile_id is None:
        return DEFAULT_PROFILE
    try:
        return DEFAULT_REGISTRY.get(profile_id)
    except ProfileError as exc:
        print(f"error: {exc}", file=streams.err)
        return None


def _validate_target(raw: str, streams: _Streams) -> Path | None:
    """Validate the scan target without bypassing Core/Engine policies.

    The check mirrors the engine's own ``resolve(strict=True)`` contract so
    the user gets an immediate, readable error for missing/unreadable
    targets. The resolved Path is what the Core receives: the CLI never
    rewrites it into shell strings and never spawns anything.
    """
    target = Path(raw)
    try:
        return target.expanduser().resolve(strict=True)
    except FileNotFoundError:
        print(f"error: target does not exist: {raw}", file=streams.err)
    except PermissionError:
        print(f"error: permission denied: {raw}", file=streams.err)
    except OSError as exc:
        print(f"error: invalid target {raw}: {exc}", file=streams.err)
    return None


def _report_result(
    result: ScanResult, profile_id: str, args: argparse.Namespace, streams: _Streams
) -> int:
    """Print the terminal result and map it to the documented exit code."""
    if args.json:
        print(json.dumps(result_to_payload(result, profile_id)), file=streams.out)
    else:
        print(format_human(result), file=streams.out)
    status = result.status.value
    if status == "infected":
        return EXIT_INFECTED
    if status == "timeout":
        return EXIT_TIMEOUT
    if status == "cancelled":
        return EXIT_CANCELLED
    if status == "error":
        return EXIT_ENGINE_ERROR
    return EXIT_OK


async def _record_best_effort(
    recorder: HistoryStore,
    result: ScanResult,
    streams: _Streams,
    profile: ScanProfile | None = None,
) -> None:
    """Persist *result* best-effort; recording failure never alters the scan.

    Mirrors the M4 contract (``HistoryError`` = storage failure): a failed
    write is reported as a warning and the original ``ScanResult`` is preserved
    unchanged, so an unavailable history layer can never retroactively turn a
    valid scan result into a scan failure.
    """
    try:
        await recorder.record_scan(result, profile=profile)
    except Exception as exc:  # defensive: recording must never break a scan
        print(f"warning: could not record scan history: {exc}", file=streams.err)


async def _scan_and_record(
    runner: ScanTaskRunner,
    target: Path,
    profile: ScanProfile,
    recorder: HistoryStore | None,
    streams: _Streams,
) -> ScanResult:
    """Run one scan and, once a :class:`ScanResult` exists, record it (best-effort).

    The Core produces the result; this Controller decides the scan is finished
    and hands the result to the History recorder. The recorder is closed in a
    ``finally`` so it is never destroyed before a completed result has been
    recorded, and failure/cancellation still releases its connection.
    """
    try:
        result = await runner.submit(target, profile=profile)
        if recorder is not None:
            await _record_best_effort(recorder, result, streams, profile=profile)
        return result
    finally:
        if recorder is not None:
            with contextlib.suppress(Exception):
                await recorder.close()


def _run_scan(
    engine: BaseAVEngine,
    target: Path,
    profile: ScanProfile,
    args: argparse.Namespace,
    streams: _Streams,
) -> int:
    """Drive one scan through the Core runner, recording its history."""
    profile_id = profile.id
    runner = ScanTaskRunner(engine, max_concurrency=1)
    recorder: HistoryStore | None = None
    try:
        recorder = _default_history_store()
    except HistoryError as exc:
        # Best-effort persistence: an unavailable history layer never blocks a scan.
        print(f"warning: history recording disabled: {exc}", file=streams.err)
    if not args.json:
        print(f"ClamGuardian\nProfile: {profile.name}\nTarget: {target}", file=streams.out)
        print("Scanning...", file=streams.out)
    try:
        result = asyncio.run(_scan_and_record(runner, target, profile, recorder, streams))
    except KeyboardInterrupt:
        # asyncio.run cancelled the main task: the engine's cancellation
        # lifecycle (SIGTERM process group → grace → SIGKILL → wait) has
        # already reaped the ClamAV subprocess. Never convert this into a
        # generic error.
        print("Scan cancelled by user", file=streams.err)
        if args.json:
            print(json.dumps(cancelled_payload(str(target), profile_id)), file=streams.out)
        return EXIT_CANCELLED
    except asyncio.CancelledError:
        print("Scan cancelled", file=streams.err)
        return EXIT_CANCELLED
    except ProfileError as exc:
        print(f"error: {exc}", file=streams.err)
        return EXIT_USAGE
    except ClamGuardianError as exc:
        print(f"error: engine failure: {exc}", file=streams.err)
        return EXIT_ENGINE_ERROR
    return _report_result(result, profile_id, args, streams)


def _cmd_scan(args: argparse.Namespace, streams: _Streams) -> int:
    profile = _resolve_profile(args.profile, streams)
    if profile is None:
        return EXIT_USAGE
    target = _validate_target(args.path, streams)
    if target is None:
        # A missing/unreadable path is the caller's usage error, not an
        # engine failure (U-04): keep exit 2 vs 3 distinguishable.
        return EXIT_USAGE
    return _run_scan(_default_engine(), target, profile, args, streams)


def run(
    argv: Sequence[str] | None = None,
    *,
    out: IO[str] | None = None,
    err: IO[str] | None = None,
) -> int:
    """Parse *argv*, dispatch the command and return the exit code.

    When custom streams are provided, ``sys.stdout``/``sys.stderr`` are
    temporarily redirected so argparse's own output (``--help``,
    ``--version``, usage errors) lands in the same streams too.
    """
    streams = _Streams(
        out if out is not None else sys.stdout, err if err is not None else sys.stderr
    )
    context = (
        contextlib.redirect_stdout(streams.out)
        if out is not None
        else contextlib.nullcontext()
    )
    with context:
        args = build_parser().parse_args(argv)
        handler = args.func
        try:
            return handler(args, streams)
        except KeyboardInterrupt:  # pragma: no cover - depends on tty timing
            print("interrupted", file=streams.err)
            return EXIT_CANCELLED


def main() -> None:
    """Console-script entry point: thin synchronous wrapper around run()."""
    raise SystemExit(run())


if __name__ == "__main__":  # pragma: no cover
    main()
