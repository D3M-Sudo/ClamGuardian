"""Headless dependency diagnostics for ClamGuardian.

This module answers one question for any front-end (CLI ``doctor``, the GTK
Diagnostics page, startup checks): *can this machine scan right now, and if
not, what should the user run to fix it?*

Everything here is pure Core: no GTK, no printing, no state mutation. The
probes only look at the system (``which``, clamd socket candidates, ``/proc``
comm entries, signature-database directories, ``/etc/os-release``) and every
probe boundary is injectable so the whole module is unit-testable without a
ClamAV installation.

When ClamGuardian runs inside a Flatpak sandbox (``FLATPAK_ID`` set) the
binaries live on the host: the lookup falls back to
``flatpak-spawn --host which <name>``, mirroring the engine's host-execution
contract (``ClamAVEngine(flatpak_host=True)``).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

#: Age after which the newest signature database is considered stale.
DATABASE_FRESH_DAYS = 14

#: clamd socket candidates probed in order (the engine's default plus the
#: conventional distro locations).
DEFAULT_SOCKET_PATHS: tuple[Path, ...] = (
    Path("/run/clamd.ctl"),
    Path("/var/run/clamav/clamd.ctl"),
    Path("/run/clamav/clamd.ctl"),
)


def _default_database_dirs() -> tuple[Path, ...]:
    """Signature-database directories (computed lazily: depends on $HOME)."""
    return (
        Path("/var/lib/clamav"),
        Path("/usr/local/var/lib/clamav"),
        Path.home() / ".local" / "share" / "clamav",
    )


#: Per-distro-family remedies, keyed by check id then distro family.
#: Families: ``debian`` (Debian/Ubuntu), ``fedora`` (Fedora/RHEL),
#: ``arch`` (Arch/Manjaro). Unknown families get a generic hint in the UI.
REMEDIES: dict[str, dict[str, str]] = {
    "clamscan": {
        "debian": "sudo apt install clamav",
        "fedora": "sudo dnf install clamav",
        "arch": "sudo pacman -S clamav",
    },
    "clamdscan": {
        "debian": "sudo apt install clamav-daemon",
        "fedora": "sudo dnf install clamav",
        "arch": "sudo pacman -S clamav",
    },
    "freshclam": {
        "debian": "sudo apt install clamav",
        "fedora": "sudo dnf install clamav-update",
        "arch": "sudo pacman -S clamav",
    },
    "clamd": {
        "debian": "sudo apt install clamav-daemon && sudo systemctl enable --now clamav-daemon",
        "fedora": "sudo dnf install clamav && sudo systemctl enable --now clamav",
        "arch": "sudo pacman -S clamav && sudo systemctl enable --now clamamd",
    },
    "databases": {
        "debian": "sudo freshclam",
        "fedora": "sudo freshclam",
        "arch": "sudo freshclam",
    },
}

#: Distro families the remedies are written for, in display order.
REMEDY_FAMILIES: tuple[str, ...] = ("debian", "fedora", "arch")


class CheckStatus(StrEnum):
    """Outcome of a single dependency check.

    ``MISSING`` is reserved for components that are not installed at all;
    ``WARNING`` covers installed-but-degraded states (daemon stopped, stale
    or absent signature databases). Only :attr:`OK` counts as healthy.
    """

    OK = "ok"
    WARNING = "warning"
    MISSING = "missing"


@dataclass(frozen=True)
class CheckResult:
    """One diagnostics result.

    ``critical`` marks components without which scanning is impossible
    (``clamscan``, signature databases): critical failures are what make the
    desktop app present the diagnostics dialog at startup and what map the
    CLI ``doctor`` command to its dedicated exit code.
    """

    id: str
    label: str
    status: CheckStatus
    detail: str
    critical: bool
    remedies: dict[str, str]


#: Injectable ``shutil.which``-compatible lookup used by the checks.
WhichFunc = Callable[[str], str | None]

#: Environment markers whose values must never reach a host subprocess.
_SECRET_ENV_MARKERS = ("TOKEN", "SECRET", "PASSWORD", "API_KEY", "APIKEY", "CREDENTIAL")


def _sanitized_environment() -> dict[str, str]:
    """Inherit the environment without credential-bearing variables.

    ``flatpak-spawn --host`` runs a host binary; there is no reason for it to
    receive the desktop session's tokens or API keys.
    """
    return {
        key: value
        for key, value in os.environ.items()
        if not any(marker in key.upper() for marker in _SECRET_ENV_MARKERS)
    }


def _host_which(name: str) -> str | None:
    """Resolve *name* on the host through ``flatpak-spawn --host``.

    Only reached from inside the Flatpak sandbox; returns ``None`` on any
    failure (missing flatpak-spawn, non-zero exit, timeout) so the caller
    degrades to "missing" instead of raising.
    """
    try:
        completed = subprocess.run(
            ["flatpak-spawn", "--host", "which", name],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            env=_sanitized_environment(),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    path = completed.stdout.strip()
    return path or None


def _default_which(env: Mapping[str, str]) -> WhichFunc:
    """Build the production lookup: ``shutil.which`` + Flatpak host fallback."""

    def lookup(name: str) -> str | None:
        found = shutil.which(name)
        if found:
            return found
        if env.get("FLATPAK_ID"):
            return _host_which(name)
        return None

    return lookup


def _parse_os_release(path: Path) -> dict[str, str]:
    """Parse an ``os-release`` file into a flat key/value mapping."""
    fields: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return fields
    for line in lines:
        key, sep, value = line.partition("=")
        if not sep or not key.strip():
            continue
        fields[key.strip()] = value.strip().strip('"')
    return fields


def detect_distro_family(os_release_path: Path = Path("/etc/os-release")) -> str:
    """Map ``/etc/os-release`` (ID + ID_LIKE) to a remedy family.

    Returns one of ``debian``, ``fedora``, ``arch`` or ``unknown``. The
    lookup walks ``ID`` first, then every word of ``ID_LIKE``, so derivatives
    (Ubuntu, Linux Mint, Manjaro, …) resolve to their base family.
    """
    fields = _parse_os_release(os_release_path)
    candidates = [fields.get("ID", ""), *fields.get("ID_LIKE", "").split()]
    for candidate in candidates:
        if candidate in {"debian", "ubuntu"}:
            return "debian"
        if candidate in {"fedora", "rhel", "centos"}:
            return "fedora"
        if candidate in {"arch", "archlinux", "manjaro"}:
            return "arch"
    return "unknown"


def _clamd_process_visible(proc_root: Path) -> bool:
    """Return True when a process named ``clamd`` is visible under *proc_root*.

    Linux-only by nature (``/proc``), but the probe degrades to ``False`` on
    any filesystem error so diagnostics never crash on unusual systems.
    """
    try:
        entries = list(proc_root.iterdir())
    except OSError:
        return False
    for entry in entries:
        try:
            comm = (entry / "comm").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        if comm == "clamd":
            return True
    return False


def _newest_database_mtime(database_dirs: Sequence[Path]) -> float | None:
    """Return the newest mtime among ``*.cvd``/``*.cld`` files, if any."""
    newest: float | None = None
    for directory in database_dirs:
        try:
            entries = list(directory.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.suffix not in {".cvd", ".cld"}:
                continue
            try:
                mtime = entry.stat().st_mtime
            except OSError:
                continue
            if newest is None or mtime > newest:
                newest = mtime
    return newest


def _binary_check(
    check_id: str,
    label: str,
    lookup: WhichFunc,
    *,
    critical: bool,
) -> CheckResult:
    found = lookup(check_id)
    if found:
        return CheckResult(
            id=check_id,
            label=label,
            status=CheckStatus.OK,
            detail=found,
            critical=critical,
            remedies={},
        )
    return CheckResult(
        id=check_id,
        label=label,
        status=CheckStatus.MISSING,
        detail=f"{check_id} not found on PATH",
        critical=critical,
        remedies=dict(REMEDIES[check_id]),
    )


def _daemon_check(
    lookup: WhichFunc, socket_paths: Sequence[Path], proc_root: Path
) -> CheckResult:
    present_sockets = [path for path in socket_paths if path.exists()]
    running = _clamd_process_visible(proc_root)
    installed = lookup("clamdscan") is not None or bool(present_sockets) or running

    if running and present_sockets:
        detail = f"daemon running (socket: {present_sockets[0]})"
    elif running:
        detail = "daemon process running (no socket found in the probed paths)"
    elif present_sockets:
        detail = f"socket present at {present_sockets[0]} but no clamd process detected"
    elif not installed:
        return CheckResult(
            id="clamd",
            label="clamd daemon",
            status=CheckStatus.MISSING,
            detail="clamd not installed; scans fall back to clamscan",
            critical=False,
            remedies=dict(REMEDIES["clamd"]),
        )
    else:
        detail = "daemon not running; scans fall back to clamscan"

    status = CheckStatus.OK if (running and present_sockets) else CheckStatus.WARNING
    return CheckResult(
        id="clamd",
        label="clamd daemon",
        status=status,
        detail=detail,
        critical=False,
        remedies={} if status is CheckStatus.OK else dict(REMEDIES["clamd"]),
    )


def _databases_check(
    database_dirs: Sequence[Path],
    *,
    now: datetime,
    fresh_days: int,
) -> CheckResult:
    newest = _newest_database_mtime(database_dirs)
    if newest is None:
        return CheckResult(
            id="databases",
            label="Signature databases",
            status=CheckStatus.WARNING,
            detail="no .cvd/.cld databases found; run freshclam to download them",
            critical=True,
            remedies=dict(REMEDIES["databases"]),
        )
    age = (now.timestamp() - newest) / 86400.0
    if age > fresh_days:
        return CheckResult(
            id="databases",
            label="Signature databases",
            status=CheckStatus.WARNING,
            detail=(
                f"newest database is {age:.0f} days old "
                f"(older than {fresh_days}); run freshclam"
            ),
            critical=True,
            remedies=dict(REMEDIES["databases"]),
        )
    return CheckResult(
        id="databases",
        label="Signature databases",
        status=CheckStatus.OK,
        detail=f"newest database is {age:.0f} day(s) old",
        critical=True,
        remedies={},
    )


def _flatpak_check(env: Mapping[str, str]) -> CheckResult:
    flatpak_id = env.get("FLATPAK_ID")
    if flatpak_id:
        detail = (
            f"running inside the {flatpak_id} sandbox; "
            "ClamAV resolved via flatpak-spawn --host"
        )
    else:
        detail = "not sandboxed; ClamAV resolved from the local PATH"
    return CheckResult(
        id="flatpak",
        label="Environment",
        status=CheckStatus.OK,
        detail=detail,
        critical=False,
        remedies={},
    )


def run_dependency_checks(
    *,
    which: WhichFunc | None = None,
    env: Mapping[str, str] | None = None,
    socket_paths: Sequence[Path] = DEFAULT_SOCKET_PATHS,
    database_dirs: Sequence[Path] | None = None,
    proc_root: Path = Path("/proc"),
    now: datetime | None = None,
    fresh_days: int = DATABASE_FRESH_DAYS,
) -> list[CheckResult]:
    """Run every dependency check and return the results, in a fixed order.

    All probe boundaries are keyword-only injectables: tests supply fake
    ``which``/``env``/paths and never depend on a real ClamAV installation.
    The function performs no writes and raises nothing: a failing probe
    degrades to a ``WARNING``/``MISSING`` result.
    """
    env = os.environ if env is None else env
    lookup = which if which is not None else _default_which(env)
    if database_dirs is None:
        database_dirs = _default_database_dirs()
    timestamp = now if now is not None else datetime.now(UTC)

    return [
        _binary_check("clamscan", "clamscan", lookup, critical=True),
        _binary_check("clamdscan", "clamdscan", lookup, critical=False),
        _binary_check("freshclam", "freshclam", lookup, critical=False),
        _daemon_check(lookup, socket_paths, proc_root),
        _databases_check(database_dirs, now=timestamp, fresh_days=fresh_days),
        _flatpak_check(env),
    ]


def critical_missing(results: Sequence[CheckResult]) -> list[CheckResult]:
    """Return the critical checks that are not :attr:`CheckStatus.OK`."""
    return [
        result for result in results if result.critical and result.status is not CheckStatus.OK
    ]


def summarize(results: Sequence[CheckResult]) -> dict[str, int]:
    """Count results per status: ``ok`` / ``warning`` / ``missing``."""
    counts = {status.value: 0 for status in CheckStatus}
    for result in results:
        counts[result.status.value] += 1
    return counts


__all__ = [
    "CheckResult",
    "CheckStatus",
    "DATABASE_FRESH_DAYS",
    "DEFAULT_SOCKET_PATHS",
    "REMEDIES",
    "REMEDY_FAMILIES",
    "WhichFunc",
    "critical_missing",
    "detect_distro_family",
    "run_dependency_checks",
    "summarize",
]