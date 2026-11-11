"""Persistent, profile-aware VirusTotal hash-report cache."""

from __future__ import annotations

import json
import math
import os
import re
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_PROFILES = frozenset({"public", "premium"})
_SCHEMA_VERSION = 2


def default_cache_path() -> Path:
    """Return the private per-user cache path beside ClamGuardian history."""
    from ..history.backend import default_history_db_path

    return default_history_db_path().with_name("virustotal-cache.db")


class VirusTotalCache:
    """SQLite cache keyed by SHA-256 and API profile."""

    def __init__(
        self,
        path: Path | None = None,
        *,
        ttl_seconds: float = 24 * 60 * 60,
        clock=time.time,
    ) -> None:
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, (int, float))
            or not math.isfinite(ttl_seconds)
            or ttl_seconds <= 0
        ):
            raise ValueError("ttl_seconds must be a positive finite number")
        self.path = Path(path) if path is not None else default_cache_path()
        self.ttl_seconds = float(ttl_seconds)
        self._clock = clock
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._lock, self._transaction() as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version > _SCHEMA_VERSION:
                raise RuntimeError(
                    f"VirusTotal cache schema {version} is newer than supported "
                    f"schema {_SCHEMA_VERSION}"
                )
            if version == 0:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS vt_hash_cache (
                        sha256 TEXT NOT NULL,
                        profile TEXT NOT NULL CHECK(profile IN ('public', 'premium')),
                        acquired_at REAL NOT NULL,
                        expires_at REAL NOT NULL,
                        report_json TEXT NOT NULL,
                        PRIMARY KEY (sha256, profile)
                    )
                    """
                )
            elif version == 1:
                # Preserve all valid v1 entries and their original expiry.
                # Since v1 held one profile per digest, each row maps directly
                # to the corresponding composite key in v2.
                connection.execute(
                    """
                    CREATE TABLE vt_hash_cache_v2 (
                        sha256 TEXT NOT NULL,
                        profile TEXT NOT NULL CHECK(profile IN ('public', 'premium')),
                        acquired_at REAL NOT NULL,
                        expires_at REAL NOT NULL,
                        report_json TEXT NOT NULL,
                        PRIMARY KEY (sha256, profile)
                    )
                    """
                )
                connection.execute(
                    """
                    INSERT INTO vt_hash_cache_v2
                        (sha256, profile, acquired_at, expires_at, report_json)
                    SELECT sha256, profile, acquired_at, expires_at, report_json
                    FROM vt_hash_cache
                    """
                )
                connection.execute("DROP TABLE vt_hash_cache")
                connection.execute(
                    "ALTER TABLE vt_hash_cache_v2 RENAME TO vt_hash_cache"
                )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_vt_hash_cache_expiry "
                "ON vt_hash_cache(expires_at)"
            )
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
        with suppress(OSError):
            os.chmod(self.path, 0o600)
        self._harden_sidecars()

    def _harden_sidecars(self) -> None:
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{self.path}{suffix}")
            with suppress(OSError):
                if sidecar.exists():
                    os.chmod(sidecar, 0o600)

    @staticmethod
    def _validate_key(sha256: str) -> str:
        if not isinstance(sha256, str) or not _SHA256_RE.fullmatch(sha256.lower()):
            raise ValueError("sha256 must be a 64-character hexadecimal digest")
        return sha256.lower()

    @staticmethod
    def _validate_profile(profile: str) -> str:
        value = getattr(profile, "value", profile)
        if value not in _ALLOWED_PROFILES:
            raise ValueError("profile must be 'public' or 'premium'")
        return str(value)

    def get(self, sha256: str, profile: str) -> dict[str, Any] | None:
        digest = self._validate_key(sha256)
        selected_profile = self._validate_profile(profile)
        now = float(self._clock())
        with self._lock, self._transaction() as connection:
            row = connection.execute(
                "SELECT expires_at, report_json FROM vt_hash_cache "
                "WHERE sha256 = ? AND profile = ?",
                (digest, selected_profile),
            ).fetchone()
            if row is None:
                return None
            expires_at, report_json = row
            if float(expires_at) <= now:
                connection.execute(
                    "DELETE FROM vt_hash_cache WHERE sha256 = ? AND profile = ?",
                    (digest, selected_profile),
                )
                return None
            try:
                report = json.loads(report_json)
            except (TypeError, json.JSONDecodeError):
                connection.execute(
                    "DELETE FROM vt_hash_cache WHERE sha256 = ? AND profile = ?",
                    (digest, selected_profile),
                )
                return None
            reported_hash = (
                report.get("sha256", digest) if isinstance(report, dict) else None
            )
            if (
                not isinstance(report, dict)
                or not isinstance(report.get("found"), bool)
                or not isinstance(reported_hash, str)
                or reported_hash.lower() != digest
                or report.get("error") is not None
            ):
                connection.execute(
                    "DELETE FROM vt_hash_cache WHERE sha256 = ? AND profile = ?",
                    (digest, selected_profile),
                )
                return None
            return report

    def put(self, sha256: str, profile: str, report: dict[str, Any]) -> None:
        digest = self._validate_key(sha256)
        selected_profile = self._validate_profile(profile)
        if not isinstance(report, dict):
            raise ValueError("report must be a dictionary")
        reported_hash = report.get("sha256", digest)
        if (
            report.get("error") is not None
            or not isinstance(report.get("found"), bool)
            or not isinstance(reported_hash, str)
            or reported_hash.lower() != digest
        ):
            return
        encoded = json.dumps(
            report, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        acquired_at = float(self._clock())
        expires_at = acquired_at + self.ttl_seconds
        with self._lock, self._transaction() as connection:
            connection.execute(
                """
                INSERT INTO vt_hash_cache
                    (sha256, profile, acquired_at, expires_at, report_json)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(sha256, profile) DO UPDATE SET
                    acquired_at = excluded.acquired_at,
                    expires_at = excluded.expires_at,
                    report_json = excluded.report_json
                """,
                (digest, selected_profile, acquired_at, expires_at, encoded),
            )
        self._harden_sidecars()

    def invalidate(self, sha256: str) -> None:
        digest = self._validate_key(sha256)
        with self._lock, self._transaction() as connection:
            connection.execute("DELETE FROM vt_hash_cache WHERE sha256 = ?", (digest,))

    def clear_expired(self) -> int:
        with self._lock, self._transaction() as connection:
            cursor = connection.execute(
                "DELETE FROM vt_hash_cache WHERE expires_at <= ?",
                (float(self._clock()),),
            )
            deleted = int(cursor.rowcount)
        self._harden_sidecars()
        return deleted


__all__ = ["VirusTotalCache", "default_cache_path"]
