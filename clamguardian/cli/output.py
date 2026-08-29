"""Output presentation layer for the CLI: human text and stable JSON.

Nothing here computes scan logic: both formatters are pure functions of a
:class:`~clamguardian.core.base.ScanResult` (plus the profile id used). The
JSON serializer produces a deterministic payload — fixed key order, plain
types only — so machine consumers can rely on the contract documented in
``docs/design/cli.md``.
"""

from __future__ import annotations

from typing import Any

from ..core.base import ScanResult
from ..core.profiles import ScanProfile

__all__ = ["format_human", "format_profiles", "result_to_payload"]


def result_to_payload(result: ScanResult, profile_id: str) -> dict[str, Any]:
    """Serialize *result* into the documented, deterministic JSON contract.

    Guaranteed keys, always present, in this exact order: ``status``,
    ``profile``, ``target``, ``engine``, ``threats``, ``files_scanned``,
    ``duration_seconds``, ``error``, ``metadata``. Values are JSON-native
    types only; the object itself is never dumped ad-hoc.
    """
    return {
        "status": result.status.value,
        "profile": profile_id,
        "target": result.target,
        "engine": result.engine,
        "threats": list(result.threats),
        "files_scanned": result.files_scanned,
        "duration_seconds": round(result.duration_seconds, 3),
        "error": result.error,
        "metadata": dict(result.metadata),
    }


def cancelled_payload(target: str, profile_id: str) -> dict[str, Any]:
    """Build the JSON contract payload for a user-requested cancellation.

    The scan never produced a :class:`ScanResult` observable here, so all
    engine-derived fields use their neutral values while keeping the same
    guaranteed key set as :func:`result_to_payload`.
    """
    return {
        "status": "cancelled",
        "profile": profile_id,
        "target": target,
        "engine": None,
        "threats": [],
        "files_scanned": 0,
        "duration_seconds": None,
        "error": "scan cancelled by user",
        "metadata": {},
    }


def format_human(result: ScanResult) -> str:
    """Render *result* as human-readable text.

    Uses only fields actually present on the result: no fabricated
    percentage, no invented file counts (the ClamAV engine does not
    currently expose streaming progress, so ``files_scanned`` is printed
    only when non-zero).
    """
    lines = [
        "Scan completed",
        f"Status: {result.status.value.upper()}",
        f"Engine: {result.engine}",
        f"Duration: {result.duration_seconds:.2f}s",
    ]
    if result.files_scanned:
        lines.insert(1, f"Files scanned: {result.files_scanned}")
    if result.threats:
        threat_lines = ["Threat detected:"]
        threat_lines.extend(f"  {threat}" for threat in result.threats)
        lines[1:1] = threat_lines
    if result.error:
        lines.append(f"Error: {result.error}")
    for key, value in sorted(result.metadata.items()):
        lines.append(f"{key}: {value}")
    return "\n".join(lines)


def format_profiles(profiles: tuple[ScanProfile, ...]) -> str:
    """Render the registry profiles as a human-readable table."""
    lines = ["Available scan profiles:"]
    for profile in profiles:
        line = f"  {profile.id:<8} {profile.name}"
        if profile.description:
            line += f" — {profile.description}"
        lines.append(line)
    return "\n".join(lines)
