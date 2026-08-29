"""History & Reporting persistence layer (M4-B).

Public surface: the immutable :class:`HistoryRecord` snapshot, the
:class:`HistoryStore` contract, and the SQLite backend. Consumers (CLI, future
GTK) should depend on :class:`HistoryStore` and inject the concrete backend.
"""

from __future__ import annotations

from .backend import SCHEMA_VERSION, SqliteHistoryStore, default_history_db_path
from .interface import HistoryError, HistoryStore
from .models import (
    AUTO_TRUNCATED_KEY,
    METADATA_MAX_BYTES,
    PROFILE_SNAPSHOT_MAX_BYTES,
    HistoryRecord,
    decode_timestamp,
    encode_timestamp,
    history_record_from_scan,
    is_valid_status,
    normalize_metadata,
    profile_snapshot,
    valid_statuses,
)

__all__ = [
    "HistoryError",
    "HistoryRecord",
    "HistoryStore",
    "SqliteHistoryStore",
    "SCHEMA_VERSION",
    "default_history_db_path",
    "AUTO_TRUNCATED_KEY",
    "METADATA_MAX_BYTES",
    "PROFILE_SNAPSHOT_MAX_BYTES",
    "decode_timestamp",
    "encode_timestamp",
    "history_record_from_scan",
    "is_valid_status",
    "normalize_metadata",
    "profile_snapshot",
    "valid_statuses",
]