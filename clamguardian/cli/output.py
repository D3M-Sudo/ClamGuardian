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
from ..history.models import HistoryRecord, encode_timestamp

__all__ = [
    "format_history_list",
    "format_history_record",
    "format_human",
    "format_profiles",
    "format_purge_result",
    "history_record_to_payload",
    "result_to_payload",
]


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


def format_purge_result(deleted: int) -> str:
    """Render a purge operation result as human-readable text."""
    return f"Purged {deleted} record(s) from history."


def format_history_list(records: list[HistoryRecord]) -> str:
    """Render a page of history records as human-readable text.

    Produces a compact, aligned table: nothing here queries the store. An empty
    page renders as a single motivating line so the terminal is never blank.
    """
    if not records:
        return "No scan history found."
    header = f"{'Started':<20} {'Status':<10} {'Target':<30} {'Threats':<10} {'Duration':>8}"
    lines = ["Scan history:", header]
    for record in records:
        started = encode_timestamp(record.started_at)[:19]
        threats = str(len(record.threats)) if record.threats else "0"
        target = record.target if len(record.target) <= 30 else "…" + record.target[-29:]
        lines.append(
            f"{started:<20} {record.status:<10} {target:<30} {threats:<10} "
            f"{record.duration_seconds:>7.2f}s"
        )
    return "\n".join(lines)


def format_history_record(record: HistoryRecord) -> str:
    """Render a single full history record (threats included) as human text."""
    lines = [
        f"Scan: {record.id}",
        f"Status: {record.status.upper()}",
        f"Target: {record.target}",
        f"Engine: {record.engine}",
        f"Profile: {record.profile_id or '-'}",
        f"Started: {encode_timestamp(record.started_at)}",
        f"Finished: {encode_timestamp(record.finished_at)}",
        f"Duration: {record.duration_seconds:.2f}s",
        f"Files scanned: {record.files_scanned}",
        f"Threats: {len(record.threats)}",
    ]
    if record.threats:
        lines.append("Detections:")
        lines.extend(f"  {threat}" for threat in record.threats)
    if record.error:
        lines.append(f"Error: {record.error}")
    if record.metadata:
        lines.append("Metadata:")
        lines.extend(f"  {key}: {value}" for key, value in sorted(record.metadata.items()))
    return "\n".join(lines)


def history_record_to_payload(record: HistoryRecord) -> dict[str, Any]:
    """Serialize *record* into a deterministic JSON contract.

    Guaranteed keys, always present, in this exact order: ``id``, ``status``,
    ``target``, ``engine``, ``profile``, ``threats``, ``files_scanned``,
    ``started_at``, ``finished_at``, ``duration_seconds``, ``error``,
    ``metadata``.
    """
    return {
        "id": record.id,
        "status": record.status,
        "target": record.target,
        "engine": record.engine,
        "profile": record.profile_id,
        "threats": list(record.threats),
        "files_scanned": record.files_scanned,
        "started_at": encode_timestamp(record.started_at),
        "finished_at": encode_timestamp(record.finished_at),
        "duration_seconds": round(record.duration_seconds, 3),
        "error": record.error,
        "metadata": dict(record.metadata),
    }
def format_profiles(profiles: tuple[ScanProfile, ...]) -> str:
    """Render the registry profiles as a human-readable table."""
    lines = ["Available scan profiles:"]
    for profile in profiles:
        line = f"  {profile.id:<8} {profile.name}"
        if profile.description:
            line += f" — {profile.description}"
        lines.append(line)
    return "\n".join(lines)
