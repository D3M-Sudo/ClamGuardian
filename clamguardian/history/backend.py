"""M4-B3 SQLite backend for the History store.

SQLite is confined to this module: neither ``core``, ``engines`` nor ``ui``
may import ``sqlite3`` for history purposes. The backend is the concrete
implementation of :class:`~clamguardian.history.interface.HistoryStore` and is
injected behind that abstraction.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import TypeVar

from ..core.base import ScanResult
from ..core.profiles import ScanProfile
from .interface import HistoryError
from .models import (
    HistoryRecord,
    ThreatIntelligenceRecord,
    decode_timestamp,
    encode_timestamp,
    history_record_from_scan,
    is_valid_status,
)

#: Schema version written via ``PRAGMA user_version`` (0 = uninitialized).
SCHEMA_VERSION = 2

_DbResult = TypeVar("_DbResult")

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

_SCHEMA_V2 = """
CREATE TABLE scan_intelligence (
    scan_id      TEXT PRIMARY KEY NOT NULL,
    provider     TEXT NOT NULL,
    profile      TEXT NOT NULL CHECK (profile IN ('public', 'premium')),
    sha256       TEXT NOT NULL CHECK (length(sha256) = 64),
    observed_at  TEXT NOT NULL,
    provenance   TEXT NOT NULL,
    status       TEXT NOT NULL CHECK (status IN ('found', 'not_found', 'error')),
    metadata_json TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scan_history (id) ON DELETE CASCADE
);
CREATE INDEX idx_scan_intelligence_sha256 ON scan_intelligence (sha256);
CREATE INDEX idx_scan_intelligence_profile ON scan_intelligence (profile);
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


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_INTELLIGENCE_PROFILES = frozenset({"public", "premium"})
_INTELLIGENCE_STATUSES = frozenset({"found", "not_found", "error"})
_INTELLIGENCE_METADATA_MAX_BYTES = 64 * 1024


def _parse_intelligence_evidence(
    raw: str | None, scan_sha256: str | None
) -> dict[str, object] | None:
    """Validate the optional VirusTotal evidence envelope before persistence."""
    if not isinstance(raw, str):
        return None
    try:
        if len(raw.encode("utf-8")) > 128 * 1024:
            return None
        payload = json.loads(raw)
    except (TypeError, UnicodeEncodeError, json.JSONDecodeError, RecursionError):
        return None
    if not isinstance(payload, dict):
        return None

    provider = payload.get("provider")
    profile = payload.get("profile")
    sha256 = payload.get("sha256")
    observed_at = payload.get("observed_at")
    provenance = payload.get("provenance")
    status = payload.get("status")
    metadata = payload.get("metadata")
    if (
        provider != "virustotal"
        or not isinstance(profile, str)
        or profile not in _INTELLIGENCE_PROFILES
        or not isinstance(sha256, str)
        or not _SHA256_RE.fullmatch(sha256)
        or not isinstance(observed_at, str)
        or not isinstance(provenance, str)
        or not provenance
        or not isinstance(status, str)
        or status not in _INTELLIGENCE_STATUSES
        or not isinstance(metadata, dict)
    ):
        return None
    try:
        decode_timestamp(observed_at)
        encoded_metadata = json.dumps(
            metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
    except (TypeError, ValueError):
        return None
    if len(encoded_metadata.encode("utf-8")) > _INTELLIGENCE_METADATA_MAX_BYTES:
        return None

    # Evidence must identify the exact object hashed by the local scan. The
    # remote report is untrusted input and cannot bind itself to another scan.
    if (
        not isinstance(scan_sha256, str)
        or not _SHA256_RE.fullmatch(scan_sha256.lower())
        or sha256 != scan_sha256.lower()
        or metadata.get("sha256") != sha256
    ):
        return None
    remote_found = metadata.get("found")
    remote_error = metadata.get("error")
    if status == "found" and remote_found is not True:
        return None
    if status == "not_found" and remote_found is not False:
        return None
    if status == "error" and (not isinstance(remote_error, str) or not remote_error):
        return None
    return {
        "provider": provider,
        "profile": profile,
        "sha256": sha256,
        "observed_at": observed_at,
        "provenance": provenance,
        "status": status,
        "metadata_json": encoded_metadata,
    }


def _row_to_intelligence_record(
    row: sqlite3.Row,
) -> ThreatIntelligenceRecord | None:
    """Rebuild one immutable VirusTotal evidence record defensively."""
    try:
        observed_at = decode_timestamp(str(row["observed_at"]))
        metadata = json.loads(str(row["metadata_json"]))
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    provider = str(row["provider"])
    profile = str(row["profile"])
    sha256 = str(row["sha256"])
    provenance = str(row["provenance"])
    status = str(row["status"])
    if (
        not isinstance(metadata, dict)
        or provider != "virustotal"
        or profile not in _INTELLIGENCE_PROFILES
        or not _SHA256_RE.fullmatch(sha256)
        or not provenance
        or status not in _INTELLIGENCE_STATUSES
    ):
        return None
    return ThreatIntelligenceRecord(
        scan_id=str(row["scan_id"]),
        provider=provider,
        profile=profile,
        sha256=sha256,
        observed_at=observed_at,
        provenance=provenance,
        status=status,
        metadata=metadata,
    )


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
            self.path.parent.mkdir(mode=_DIR_MODE, parents=True)
        except FileExistsError:
            # Pre-existing directory (possibly shared): never change its mode.
            pass
        except OSError as exc:
            raise HistoryError(f"cannot create history directory: {exc}") from exc
        else:
            try:
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
            elif version == 1:
                # Store remote intelligence independently from the ClamAV
                # verdict, linked by the immutable scan-history identifier.
                conn.execute("BEGIN IMMEDIATE")
                try:
                    for statement in _iter_schema_statements(_SCHEMA_V2):
                        conn.execute(statement)
                    conn.execute(f"PRAGMA user_version = {version + 1}")
                    conn.execute("COMMIT")
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
                version += 1
            else:
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

    def _execute_db(self, operation: Callable[[sqlite3.Connection], _DbResult]) -> _DbResult:
        """Run one complete connection operation under the lifecycle lock."""
        with self._lock:
            conn = self._require_conn()
            try:
                return operation(conn)
            except sqlite3.Error as exc:
                raise HistoryError(
                    f"history database operation failed: {exc}"
                ) from exc

    async def record_scan(
        self, result: ScanResult, profile: ScanProfile | None = None
    ) -> HistoryRecord:
        """Persist a scan atomically without blocking the caller's event loop."""
        intelligence = _parse_intelligence_evidence(
            result.metadata.get("threat_intelligence") if result.metadata else None,
            result.metadata.get("sha256") if result.metadata else None,
        )
        record = history_record_from_scan(result, profile=profile)
        await asyncio.to_thread(self._record_scan_sync, record, intelligence)
        return record

    def _record_scan_sync(
        self, record: HistoryRecord, intelligence: dict[str, object] | None
    ) -> None:
        """Perform the atomic scan write in a worker thread."""
        def persist(conn: sqlite3.Connection) -> None:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "INSERT INTO scan_history (" + ", ".join(_HISTORY_COLUMNS)
                    + ") VALUES (" + ", ".join("?" for _ in _HISTORY_COLUMNS) + ")",
                    (
                        record.id, record.target, record.status, record.engine,
                        record.files_scanned, record.error, record.profile_id,
                        json.dumps(
                            dict(record.profile_snapshot),
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        if record.profile_snapshot is not None else None,
                        json.dumps(dict(record.metadata), sort_keys=True, separators=(",", ":")),
                        encode_timestamp(record.started_at), encode_timestamp(record.finished_at),
                        encode_timestamp(record.created_at), record.duration_seconds,
                    ),
                )
                self._insert_threats(conn, record.id, record.threats)
                if intelligence is not None:
                    conn.execute(
                        """INSERT INTO scan_intelligence (
                            scan_id, provider, profile, sha256, observed_at,
                            provenance, status, metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            record.id, intelligence["provider"], intelligence["profile"],
                            intelligence["sha256"], intelligence["observed_at"],
                            intelligence["provenance"], intelligence["status"],
                            intelligence["metadata_json"],
                        ),
                    )
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
        self._execute_db(persist)
        self._harden_aux_files()

    async def get_scan_intelligence(self, scan_id: str) -> ThreatIntelligenceRecord | None:
        """Return the separate VirusTotal assessment associated with a scan."""
        def query(conn: sqlite3.Connection) -> ThreatIntelligenceRecord | None:
            row = conn.execute(
                "SELECT * FROM scan_intelligence WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            return _row_to_intelligence_record(row) if row is not None else None
        return await asyncio.to_thread(self._execute_db, query)

    async def get_scan(self, scan_id: str) -> HistoryRecord | None:
        """Return the full record for scan_id, including threats, or None."""
        def query(conn: sqlite3.Connection) -> HistoryRecord | None:
            row = conn.execute("SELECT * FROM scan_history WHERE id = ?", (scan_id,)).fetchone()
            if row is None:
                return None
            record = _row_to_record(row)
            return replace(record, threats=_attach_threats(conn, record.id)) if record else None
        return await asyncio.to_thread(self._execute_db, query)

    async def list_scans(
        self, *, status: str | None = None, profile_id: str | None = None,
        since: datetime | None = None, until: datetime | None = None,
        limit: int = 100, offset: int = 0, ascending: bool = False,
    ) -> list[HistoryRecord]:
        """Return scan summaries ordered by started_at."""
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
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        order = "ASC" if ascending else "DESC"
        sql = f"SELECT * FROM scan_history {where} ORDER BY started_at {order} LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        def query(conn: sqlite3.Connection) -> list[HistoryRecord]:
            rows = conn.execute(sql, params).fetchall()
            return [record for row in rows if (record := _row_to_record(row)) is not None]
        return await asyncio.to_thread(self._execute_db, query)

    async def delete_scan(self, scan_id: str) -> bool:
        """Delete one scan and cascade its dependent rows."""
        def delete(conn: sqlite3.Connection) -> bool:
            return conn.execute("DELETE FROM scan_history WHERE id = ?", (scan_id,)).rowcount > 0
        return await asyncio.to_thread(self._execute_db, delete)

    async def clear_history(self) -> int:
        """Delete all scans and return the master row count."""
        def clear(conn: sqlite3.Connection) -> int:
            return conn.execute("DELETE FROM scan_history").rowcount
        return await asyncio.to_thread(self._execute_db, clear)

    async def purge(self, *, before: datetime | None = None, status: str | None = None) -> int:
        """Delete scans matching the requested criteria."""
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
        where = "WHERE " + " AND ".join(clauses)
        def delete(conn: sqlite3.Connection) -> int:
            return conn.execute(f"DELETE FROM scan_history {where}", params).rowcount
        return await asyncio.to_thread(self._execute_db, delete)

    async def count_scans(self, *, status: str | None = None) -> int:
        """Return the number of stored scans, optionally filtered by status."""
        if status is not None and not is_valid_status(status):
            raise ValueError(f"unknown status: {status!r}")
        sql = "SELECT COUNT(*) FROM scan_history"
        params: tuple[object, ...] = ()
        if status is not None:
            sql += " WHERE status = ?"
            params = (status,)
        def count(conn: sqlite3.Connection) -> int:
            row = conn.execute(sql, params).fetchone()
            return int(row[0]) if row else 0
        return await asyncio.to_thread(self._execute_db, count)

    async def close(self) -> None:
        """Close the connection under the same lock as every other operation."""
        await asyncio.to_thread(self._close_sync)

    def _close_sync(self) -> None:
        with self._lock:
            conn = self._conn
            if conn is None:
                return
            try:
                conn.close()
            except sqlite3.Error as exc:
                raise HistoryError(f"cannot close history database: {exc}") from exc
            finally:
                self._conn = None
