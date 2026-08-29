"""M4-B1 data model: immutable history snapshots and serialization helpers.

The persistence layer is deliberately decoupled from the Core: a
:class:`HistoryRecord` is a frozen snapshot of a completed scan, produced from
a :class:`~clamguardian.core.base.ScanResult` plus the profile that produced
it. It holds only JSON-safe, snapshot-copied data -- never references to live
Core objects.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, fields
from datetime import UTC, datetime
from typing import Any

from ..core.base import ScanResult
from ..core.profiles import ScanProfile

#: Budgets from the M4-A design. The metadata serialized limit is ~8 KiB and
#: the combined metadata + profile_snapshot budget is ~32 KiB. Capping each JSON
#: column at 8 KiB keeps any actual combination well within that total budget.
METADATA_MAX_BYTES = 8 * 1024
PROFILE_SNAPSHOT_MAX_BYTES = 8 * 1024
#: Marker embedded in a serialized payload when deterministic truncation ran.
AUTO_TRUNCATED_KEY = "__cg_history_truncated__"

_PROFILE_FIELDS = tuple(field.name for field in fields(ScanProfile))

_CLEAN_STATES = frozenset({"clean", "infected", "error", "timeout", "cancelled"})


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def encode_timestamp(value: datetime) -> str:
    """Serialize *value* to a round-trippable ISO-8601 UTC string."""
    return _as_utc(value).isoformat()


def decode_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 string back into a timezone-aware UTC datetime.

    Raises :class:`ValueError` on malformed input.
    """
    return _as_utc(datetime.fromisoformat(value))


def _bounded_json(data: dict[str, Any], limit_bytes: int) -> str:
    """Serialize *data* to compact JSON, deterministically dropping the largest
    values first when *limit_bytes* is exceeded, and tagging the result via
    :data:`AUTO_TRUNCATED_KEY` so consumers can detect truncation.

    Never raises and never produces an invalid blob: the marker alone is always
    tiny enough to serialize.
    """

    def encode(payload: dict[str, Any]) -> bytes:
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")

    base: dict[str, Any] = {k: v for k, v in data.items() if k != AUTO_TRUNCATED_KEY}
    if len(encode(base)) <= limit_bytes:
        return json.dumps(
            base, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )

    trimmed = dict(base)
    marker: dict[str, Any] = {AUTO_TRUNCATED_KEY: "1"}
    while trimmed and len(encode({**trimmed, **marker})) > limit_bytes:
        victim = max(trimmed, key=lambda k: (len(str(trimmed[k])), str(k)))
        del trimmed[victim]
    return json.dumps(
        {**trimmed, **marker}, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def normalize_metadata(metadata: dict[str, str] | None) -> dict[str, str]:
    """Copy and bound *metadata* into a JSON-safe, size-capped dict.

    Every value is coerced to ``str`` (the Core type is ``dict[str, str]`` but
    the source is treated as untrusted). Oversized payloads are
    deterministically truncated and tagged -- never lost entirely, never raised.
    """
    if not metadata:
        return {}
    normalized = {str(k): str(v) for k, v in metadata.items()}
    return json.loads(_bounded_json(normalized, METADATA_MAX_BYTES))


def profile_snapshot(profile: ScanProfile | None) -> dict[str, object] | None:
    """Return a JSON-safe copy of the profile configuration, or ``None``.

    A snapshot *copy* (not a reference to the :class:`ScanProfile`) so later
    changes to any profile instance cannot alter a stored historical record.
    """
    if profile is None:
        return None
    snap = {name: getattr(profile, name) for name in _PROFILE_FIELDS}
    return json.loads(_bounded_json(snap, PROFILE_SNAPSHOT_MAX_BYTES))


def is_valid_status(status: str) -> bool:
    """Return whether *status* is one of the persisted ``ScanStatus`` values."""
    return status in _CLEAN_STATES


def valid_statuses() -> tuple[str, ...]:
    """All persisted ``ScanStatus`` values in stable order."""
    return ("clean", "infected", "error", "timeout", "cancelled")


@dataclass(frozen=True, slots=True)
class HistoryRecord:
    """Immutable snapshot of a completed scan, safe for persistence.

    ``started_at``/``finished_at`` are the authoritative temporal source;
    ``duration_seconds`` is a cached, derived value. ``metadata`` and
    ``profile_snapshot`` are snapshot *copies* -- the record never holds live
    references to Core objects. ``threats`` preserves the original order.
    """

    id: str
    target: str
    status: str
    engine: str
    files_scanned: int
    threats: tuple[str, ...]
    error: str | None
    profile_id: str | None
    profile_snapshot: dict[str, object] | None
    metadata: dict[str, str]
    started_at: datetime
    finished_at: datetime
    created_at: datetime
    duration_seconds: float


def history_record_from_scan(
    result: ScanResult,
    *,
    record_id: str | None = None,
    profile: ScanProfile | None = None,
    created_at: datetime | None = None,
) -> HistoryRecord:
    """Build a persistent snapshot :class:`HistoryRecord` from *result*.

    The ``clean`` boolean of ``ScanResult`` is intentionally dropped (it is
    derived from ``status``). ``duration_seconds`` is recomputed from the
    timestamps rather than treated as primary data. All mutable inputs are
    snapshot-copied. ``status`` is stored as the stable enum value string.
    """
    started = _as_utc(result.started_at)
    finished = _as_utc(result.finished_at)
    duration = max(0.0, (finished - started).total_seconds())
    snap = profile_snapshot(profile)
    return HistoryRecord(
        id=record_id or uuid.uuid4().hex,
        target=str(result.target),
        status=result.status.value,
        engine=result.engine,
        files_scanned=int(result.files_scanned or 0),
        threats=tuple(str(t) for t in result.threats),
        error=result.error,
        profile_id=profile.id if profile is not None else None,
        profile_snapshot=snap,
        metadata=normalize_metadata(result.metadata),
        started_at=started,
        finished_at=finished,
        created_at=_as_utc(created_at or datetime.now(UTC)),
        duration_seconds=duration,
    )