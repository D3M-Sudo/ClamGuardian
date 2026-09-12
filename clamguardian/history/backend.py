"""M4-B3 SQLite backend for the History store.

SQLite is confined to this module: neither ``core``, ``engines`` nor ``ui``
may import ``sqlite3`` for history purposes. The backend is the concrete
implementation of :class:`~clamguardian.history.interface.HistoryStore` and is
injected behind that abstraction.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from ..core.base import ScanResult
from ..core.profiles import ScanProfile
from .interface import HistoryError
from .models import (
    HistoryRecord,
    decode_timestamp,
    encode_timestamp,
    history_record_from_scan,
    is_valid_status,
)

#: Schema version written via ``PRAGMA user_version`` (0 = uninitialized).
SCHEMA_VERSION = 1

_SCHEMA_V1 = """
CREATE TABLE scan_history (
    id               TEXT PRIMARY KEY,
    target           TEXT NOT NULL,
    status           TEXT NOT NULL CHECK (
        status IN ('clean', 'infected', 'error', 'timeout', 'cancelled')
    ),
    engine           TEXT NOT NULL,
    files_scanned    INTEGER NOT NULL DEFAULT 0,
    error            TEXT,
    profile_id       TEXT,
    profile_snapshot TEXT,
    metadata_json    TEXT,
    started_at       TEXT NOT NULL,
    finished_at      TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    duration_seconds REAL
);
CREATE TABLE scan_threats (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id  TEXT NOT NULL,
    name     TEXT NOT NULL,
    position INTEGER NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scan_history (id) ON DELETE CASCADE
);
CREATE INDEX idx_scan_history_status    ON scan_history (status);
CREATE INDEX idx_scan_history_started_at ON scan_history (started_at);
CREATE INDEX idx_scan_history_profile   ON scan_history (profile_id);
CREATE INDEX idx_scan_threats_scan_id   ON scan_threats (scan_id);
CREATE INDEX idx_scan_threats_name      ON scan_threats (name);
"""

_HISTORY_COLUMNS = (
    "id",
    "target",
    "status",
    "engine",
    "files_scanned",
    "error",
    "profile_id",
    "profile_snapshot",
    "metadata_json",
    "started_at",
    "finished_at",
    "created_at",
    "duration_seconds",
)

_DB_MODE = 0o600
_DIR_MODE = 0o700


def default_history_db_path() -> Path:
    """Resolve the default database location.

    Preference order: ``$XDG_DATA_HOME/clamguardian/history.db``, then
    ``~/.local/share/clamguardian/history.db``. ``~/.clamguardian`` is never
    hardcoded.
    """
    xdg_data_home = os.environ.get("XDG_DATA_HOME")
    if xdg_data_home:
        return Path(xdg_data_home).expanduser() / "clamguardian" / "history.db"
    return Path.home() / ".local" / "share" / "clamguardian" / "history.db"


def _json_loads(text: str | None, default: object) -> object:
    """Parse a JSON column defensively; return *default* on ``None``/malformed."""
    if not text:
        return default
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return default


def _parse_snapshot(text: str | None) -> dict[str, object] | None:
    """Parse the ``profile_snapshot`` JSON column; ``None`` if absent/bad."""
    parsed = _json_loads(text, None)
    if not isinstance(parsed, dict):
        return None
    return {str(k): v for k, v in parsed.items()}


def _parse_metadata(text: str | None) -> dict[str, str]:
    """Parse the ``metadata_json`` column into ``dict[str, str]``; ``{}`` if bad."""
    parsed = _json_loads(text, {})
    if not isinstance(parsed, dict):
        return {}
    return {str(k): str(v) for k, v in parsed.items()}


def _iter_schema_statements(script: str) -> list[str]:
    """Split a static DDL script into individual executable statements."""
    return [s.strip() for s in script.split(";") if s.strip()]


def _row_to_record(row: sqlite3.Row) -> HistoryRecord | None:
    """Rebuild a HistoryRecord from a ``scan_history`` row (threats empty).

    Defensive parsing policy: a row that cannot be converted into a *valid*
    record (malformed timestamps, unknown status, non-scalar corruption) is
    reported as ``None`` and skipped by callers instead of crashing the whole
    query. Valid data is never silently altered.
    """
    if not is_valid_status(str(row["status"])):
        return None
    try:
        started_at = decode_timestamp(str(row["started_at"]))
        finished_at = decode_timestamp(str(row["finished_at"]))
        created_at = decode_timestamp(str(row["created_at"]))
    except (ValueError, TypeError):
        return None
    return HistoryRecord(
        id=str(row["id"]),
        target=str(row["target"]),
        status=str(row["status"]),
        engine=str(row["engine"]),
        files_scanned=int(row["files_scanned"] or 0),
        threats=tuple(),
        error=row["error"],
        profile_id=row["profile_id"],
        profile_snapshot=_parse_snapshot(row["profile_snapshot"]),
        metadata=_parse_metadata(row["metadata_json"]),
        started_at=started_at,
        finished_at=finished_at,
        created_at=created_at,
        duration_seconds=float(row["duration_seconds"] or 0.0),
    )


def _attach_threats(conn: sqlite3.Connection, record_id: str) -> tuple[str, ...]:
    """Load ordered threat names for *record_id*."""
    cur = conn.execute(
        "SELECT name FROM scan_threats WHERE scan_id = ? ORDER BY position ASC",
        (record_id,),
    )
    return tuple(str(r[0]) for r in cur.fetchall())


class SqliteHistoryStore:
    """SQLite-backed :class:`HistoryStore` implementation.

    A single connection is reused for the store's lifetime. Writes are guarded
    by a backend-confined lock; ``record_scan`` (plus its threat rows) is one
    atomic transaction. The default path is resolved via
    :func:`default_history_db_path`.
    """

    def __init__(
        self,
        path: Path | None = None,
        *,
        create: bool = True,
    ) -> None:
        self.path = Path(path) if path is not None else default_history_db_path()
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        if create:
            self._initialize()

    # -- setup -----------------------------------------------------------

    def _initialize(self) -> None:
        try:
            self.path.parent.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
            os.chmod(self.path.parent, _DIR_MODE)
        except OSError as exc:
            raise HistoryError(f"cannot create history directory: {exc}") from exc

        existed = self.path.exists()
        try:
            # check_same_thread=False: the single connection may be reached
            # from worker threads (e.g. asyncio.to_thread consumers). This is
            # safe because *every* access is serialized by ``self._lock``.
            conn = sqlite3.connect(self.path, timeout=5.0, check_same_thread=False)
        except sqlite3.Error as exc:
            raise HistoryError(f"cannot open history database: {exc}") from exc

        self._configure(conn)
        try:
            if not existed:
                os.chmod(self.path, _DB_MODE)
        except OSError:
            # Permissions are best-effort on filesystems that do not honour
            # them (FAT, some sandboxes); the database still works.
            pass

        try:
            self._migrate(conn)
        except (sqlite3.Error, HistoryError) as exc:
            conn.close()
            raise HistoryError(f"history schema init failed: {exc}") from exc
        self._conn = conn
        self._harden_aux_files()

    def _harden_aux_files(self) -> None:
        """Best-effort ``0600`` on the WAL/SHM sidecar files.

        SQLite creates ``<db>-wal`` and ``<db>-shm`` with mode ``0644 & ~umask``,
        which may be group/world readable. They hold the same sensitive data as
        the database (targets, threats, metadata), so tighten them whenever they
        exist. Files may be (re)created lazily by SQLite; callers re-invoke this
        after write transactions. Failure is non-fatal (see ``_initialize``).
        """
        for suffix in ("-wal", "-shm"):
            try:
                sidecar = self.path.with_name(self.path.name + suffix)
                if sidecar.exists():
                    os.chmod(sidecar, _DB_MODE)
            except OSError:
                pass

    @staticmethod
    def _configure(conn: sqlite3.Connection) -> None:
        # Autocommit mode: every statement commits immediately unless wrapped
        # in an explicit BEGIN..COMMIT (used by record_scan). This guarantees
        # DELETE / clear visibility to concurrent readers.
        conn.isolation_level = None
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row

    @staticmethod
    def _current_version(conn: sqlite3.Connection) -> int:
        row = conn.execute("PRAGMA user_version").fetchone()
        return int(row[0]) if row else 0

    @staticmethod
    def _run_migrations(conn: sqlite3.Connection, target: int) -> None:
        current = SqliteHistoryStore._current_version(conn)
        if current > target:
            # A database written by a newer ClamGuardian must never be opened
            # with older (incompatible) schema expectations: fail loudly.
            raise HistoryError(
                f"history database schema version {current} is newer than "
                f"the supported version {target}"
            )
        version = current
        while version < target:
            if version == 0:
                # Explicit transaction: the whole DDL set AND the user_version
                # bump commit atomically or not at all. ``executescript`` does
                # NOT provide this guarantee under isolation_level=None (each
                # statement would autocommit), so the statements are run
                # individually inside BEGIN IMMEDIATE / COMMIT.
                conn.execute("BEGIN IMMEDIATE")
                try:
                    for statement in _iter_schema_statements(_SCHEMA_V1):
                        conn.execute(statement)
                    conn.execute(f"PRAGMA user_version = {version + 1}")
                    conn.execute("COMMIT")
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
                version += 1
            else:
                # Future incremental migrations (1 -> 2, 2 -> 3, ...) are
                # appended here; none exist yet.
                raise HistoryError(
                    f"unsupported schema version {version}: no migration defined"
                )

    def _migrate(self, conn: sqlite3.Connection) -> None:
        SqliteHistoryStore._run_migrations(conn, SCHEMA_VERSION)

    # -- helpers ---------------------------------------------------------

    def _require_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise HistoryError("history store is not initialized")
        return self._conn

    def _insert_threats(
        self, conn: sqlite3.Connection, scan_id: str, threats: tuple[str, ...]
    ) -> None:
        """Insert threat rows. Overridable seam for rollback tests."""
        for position, name in enumerate(threats):
            conn.execute(
                "INSERT INTO scan_threats (scan_id, name, position) VALUES (?, ?, ?)",
                (scan_id, str(name), position),
            )

    # -- public async API ----------------------------------------------

    async def record_scan(
        self, result: ScanResult, profile: ScanProfile | None = None
    ) -> HistoryRecord:
        """Persist *result* atomically (master + threats) and return its record."""
        record = history_record_from_scan(result, profile=profile)
        conn = self._require_conn()
        with self._lock:
            try:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    conn.execute(
                        "INSERT INTO scan_history ("
                        + ", ".join(_HISTORY_COLUMNS)
                        + ") VALUES ("
                        + ", ".join("?" for _ in _HISTORY_COLUMNS)
                        + ")",
                        (
                            record.id,
                            record.target,
                            record.status,
                            record.engine,
                            record.files_scanned,
                            record.error,
                            record.profile_id,
                            (
                                json.dumps(
                                    dict(record.profile_snapshot),
                                    sort_keys=True,
                                    separators=(",", ":"),
                                )
                                if record.profile_snapshot is not None
                                else None
                            ),
                            json.dumps(
                                dict(record.metadata), sort_keys=True, separators=(",", ":")
                            ),
                            encode_timestamp(record.started_at),
                            encode_timestamp(record.finished_at),
                            encode_timestamp(record.created_at),
                            record.duration_seconds,
                        ),
                    )
                    self._insert_threats(conn, record.id, record.threats)
                    conn.execute("COMMIT")
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
                # WAL/SHM sidecars may have been (re)created by this write.
                self._harden_aux_files()
            except sqlite3.Error as exc:
                raise HistoryError(f"failed to record scan: {exc}") from exc
        return record

    async def get_scan(self, scan_id: str) -> HistoryRecord | None:
        """Return the full record for *scan_id* (including threats) or ``None``."""
        conn = self._require_conn()
        with self._lock:
            row = conn.execute(
                "SELECT * FROM scan_history WHERE id = ?", (scan_id,)
            ).fetchone()
            if row is None:
                return None
            record = _row_to_record(row)
            if record is None:
                # Malformed row: treated as missing per the defensive policy.
                return None
            threats = _attach_threats(conn, record.id)
        return replace(record, threats=threats)

    async def list_scans(
        self,
        *,
        status: str | None = None,
        profile_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
        ascending: bool = False,
    ) -> list[HistoryRecord]:
        """Return scan summaries ordered by ``started_at`` (default descending).

        Threat details are intentionally not loaded per row (use
        :meth:`get_scan` for the full record).
        """
        if limit <= 0:
            raise ValueError("limit must be positive")
        if offset < 0:
            raise ValueError("offset must be non-negative")
        if status is not None and not is_valid_status(status):
            raise ValueError(f"unknown status: {status!r}")

        clauses: list[str] = []
        params: list[object] = []
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        if profile_id is not None:
            clauses.append("profile_id = ?")
            params.append(profile_id)
        if since is not None:
            clauses.append("started_at >= ?")
            params.append(encode_timestamp(since))
        if until is not None:
            clauses.append("started_at <= ?")
            params.append(encode_timestamp(until))

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        order = "ASC" if ascending else "DESC"
        sql = (
            f"SELECT * FROM scan_history {where} "
            f"ORDER BY started_at {order} LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])
        conn = self._require_conn()
        with self._lock:
            rows = conn.execute(sql, params).fetchall()
        records: list[HistoryRecord] = []
        for row in rows:
            record = _row_to_record(row)
            if record is not None:  # skip malformed rows defensively
                records.append(record)
        return records

    async def delete_scan(self, scan_id: str) -> bool:
        """Delete one scan, cascading its threats; ``False`` if it did not exist."""
        conn = self._require_conn()
        with self._lock:
            cur = conn.execute("DELETE FROM scan_history WHERE id = ?", (scan_id,))
            return cur.rowcount > 0

    async def clear_history(self) -> int:
        """Delete all scans (cascading threats) and return the master row count."""
        conn = self._require_conn()
        with self._lock:
            cur = conn.execute("DELETE FROM scan_history")
            return cur.rowcount

    async def purge(
        self,
        *,
        before: datetime | None = None,
        status: str | None = None,
    ) -> int:
        """Delete scans matching the criteria and return the row count.

        ``before`` selects records whose ``started_at`` is strictly older
        (exclusive boundary). ``status`` restricts the operation to one state.
        At least one criterion is required: ``purge()`` with neither is a
        :class:`ValueError` so it can never silently clear the whole history.
        """
        if before is None and status is None:
            raise ValueError("purge requires at least one of: before, status")
        if status is not None and not is_valid_status(status):
            raise ValueError(f"unknown status: {status!r}")

        clauses: list[str] = []
        params: list[object] = []
        if before is not None:
            clauses.append("started_at < ?")
            params.append(encode_timestamp(before))
        if status is not None:
            clauses.append("status = ?")
            params.append(status)

        where = f"WHERE {' AND '.join(clauses)}"
        conn = self._require_conn()
        with self._lock:
            cur = conn.execute(f"DELETE FROM scan_history {where}", params)
            return cur.rowcount

    async def count_scans(self, *, status: str | None = None) -> int:
        """Return the number of stored scans, optionally filtered by *status*."""
        conn = self._require_conn()
        if status is not None and not is_valid_status(status):
            raise ValueError(f"unknown status: {status!r}")
        query = "SELECT COUNT(*) FROM scan_history"
        params: tuple[object, ...] = ()
        if status is not None:
            query += " WHERE status = ?"
            params = (status,)
        row = conn.execute(query, params).fetchone()
        return int(row[0]) if row else 0

    async def close(self) -> None:
        """Close the underlying connection, if open."""
        conn = self._conn
        self._conn = None
        if conn is not None:
            conn.close()