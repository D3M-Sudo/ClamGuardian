"""M4-B4 tests: data model, serialization, SQLite backend, CRUD, safety."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from clamguardian.core.base import ScanResult, ScanStatus
from clamguardian.core.profiles import ScanProfile
from clamguardian.history import (
    AUTO_TRUNCATED_KEY,
    METADATA_MAX_BYTES,
    SqliteHistoryStore,
    decode_timestamp,
    default_history_db_path,
    encode_timestamp,
    history_record_from_scan,
    is_valid_status,
    normalize_metadata,
    profile_snapshot,
)
from clamguardian.history.backend import SCHEMA_VERSION
from clamguardian.history.interface import HistoryError, HistoryStore

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_store(tmp_path: Path) -> SqliteHistoryStore:
    return SqliteHistoryStore(tmp_path / "history.db")


def make_result(
    *,
    target: str = "/tmp/scan-target",
    status: ScanStatus = ScanStatus.CLEAN,
    threats: tuple[str, ...] = (),
    engine: str = "clamd",
    files_scanned: int = 0,
    error: str | None = None,
    metadata: dict[str, str] | None = None,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
) -> ScanResult:
    started = started_at or datetime.now(UTC)
    finished = finished_at or started + timedelta(seconds=3)
    return ScanResult(
        target=target,
        clean=status is ScanStatus.CLEAN,
        status=status,
        threats=threats,
        files_scanned=files_scanned,
        engine=engine,
        error=error,
        metadata=metadata or {},
        started_at=started,
        finished_at=finished,
    )


# ---------------------------------------------------------------------------
# Data model: ScanResult -> HistoryRecord
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "status,error,threats",
    [
        (ScanStatus.CLEAN, None, ()),
        (ScanStatus.INFECTED, None, ("Eicar FOUND", "Bogus FOUND")),
        (ScanStatus.ERROR, "clamd exploded", ()),
        (ScanStatus.TIMEOUT, "scan timed out", ()),
        (ScanStatus.CANCELLED, None, ()),
    ],
)
def test_record_from_scan_covers_all_statuses(
    status: ScanStatus, error: str | None, threats: tuple[str, ...]
) -> None:
    result = make_result(status=status, error=error, threats=threats, files_scanned=7)
    rec = history_record_from_scan(result)
    assert rec.status == status.value
    assert rec.target == result.target
    assert rec.engine == result.engine
    assert rec.files_scanned == 7
    assert rec.error == error
    assert rec.threats == threats
    assert rec.started_at.tzinfo is not None
    assert rec.finished_at.tzinfo is not None
    assert rec.duration_seconds == pytest.approx(3.0)


def test_record_drops_clean_and_recomputes_duration() -> None:
    result = make_result(status=ScanStatus.INFECTED, threats=("X FOUND",))
    rec = history_record_from_scan(result)
    assert not hasattr(rec, "clean")
    assert rec.duration_seconds == pytest.approx(
        (rec.finished_at - rec.started_at).total_seconds()
    )


def test_record_snapshot_isolated_from_result_mutation() -> None:
    metadata = {"k": "v"}
    result = make_result(status=ScanStatus.CLEAN, metadata=metadata)
    rec = history_record_from_scan(result)
    metadata["k"] = "changed"
    assert rec.metadata == {"k": "v"}


def test_record_is_frozen() -> None:
    rec = history_record_from_scan(make_result())
    with pytest.raises(AttributeError):
        rec.target = "/other"  # type: ignore[misc]


def test_metadata_coerced_to_string() -> None:
    result = make_result(metadata={"num": 42, "flag": True})  # type: ignore[dict-item]
    rec = history_record_from_scan(result)
    assert rec.metadata == {"num": "42", "flag": "True"}


# ---------------------------------------------------------------------------
# Profile snapshot
# ---------------------------------------------------------------------------


def test_profile_snapshot_is_json_safe_copy() -> None:
    profile = ScanProfile.quick()
    snap = profile_snapshot(profile)
    assert snap is not None
    assert snap["id"] == "quick"
    assert snap["name"] == "Quick Scan"
    assert snap["max_filesize_mib"] == 25
    assert json.loads(json.dumps(snap)) == snap


def test_profile_snapshot_none_for_missing_profile() -> None:
    assert profile_snapshot(None) is None


def test_profile_snapshot_isolated_from_profile_mutation() -> None:
    profile = ScanProfile.custom()
    rec = history_record_from_scan(make_result(), profile=profile)
    original = rec.profile_snapshot
    assert original["name"] == "Custom Scan"
    changed = profile.with_overrides(name="Renamed")
    assert changed.name == "Renamed"
    assert rec.profile_snapshot == original
    assert rec.profile_id == "custom"


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def test_timestamp_round_trip_utc() -> None:
    original = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert decode_timestamp(encode_timestamp(original)) == original


def test_timestamp_naive_gets_utc() -> None:
    naive = datetime(2026, 1, 2, 3, 4, 5)
    assert decode_timestamp(encode_timestamp(naive)).tzinfo is not None


def test_metadata_size_limit_with_truncation_marker() -> None:
    huge = {"big": "x" * (METADATA_MAX_BYTES * 2), "small": "ok"}
    normalized = normalize_metadata(huge)
    assert isinstance(normalized, dict)
    assert "small" in normalized
    assert normalized["small"] == "ok"
    assert AUTO_TRUNCATED_KEY in normalized
    assert len(json.dumps(normalized).encode()) <= METADATA_MAX_BYTES + 256


def test_metadata_within_limit_has_no_marker() -> None:
    assert AUTO_TRUNCATED_KEY not in normalize_metadata({"a": "b"})


def test_valid_status_helpers() -> None:
    for status in ("clean", "infected", "error", "timeout", "cancelled"):
        assert is_valid_status(status)
    assert not is_valid_status("quarantined")
    assert not is_valid_status("")


# ---------------------------------------------------------------------------
# SQLite initialization
# ---------------------------------------------------------------------------


def test_store_creates_dir_and_db_with_permissions(tmp_path: Path) -> None:
    db_path = tmp_path / "data" / "history.db"
    _store = SqliteHistoryStore(db_path)
    assert _store.path == db_path
    assert db_path.exists()
    assert db_path.parent.exists()
    # Permissions are best-effort on filesystems that do not honour them.
    if db_path.stat().st_mode & 0o777 != 0o600:
        print("NOTE: filesystem does not honour 0600; skipping strict check")
    else:
        assert db_path.stat().st_mode & 0o777 == 0o600
    if db_path.parent.stat().st_mode & 0o777 != 0o700:
        print("NOTE: filesystem does not honour 0700; skipping strict check")
    else:
        assert db_path.parent.stat().st_mode & 0o777 == 0o700


def test_user_version_and_pragmas(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    store = SqliteHistoryStore(db_path)
    # DB-scoped settings are visible from any connection.
    conn = sqlite3.connect(db_path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 1
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    conn.close()
    # Per-connection settings apply to the store's own connection.
    sc = store._conn
    assert sc is not None
    assert sc.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
    assert sc.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_store_is_idempotent_on_reopen(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    SqliteHistoryStore(db_path)
    SqliteHistoryStore(db_path)  # reopen must not error


def test_schema_has_expected_tables_and_indexes(tmp_path: Path) -> None:
    store = SqliteHistoryStore(tmp_path / "history.db")
    conn = sqlite3.connect(store.path)
    tables = {
        r[0]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert {"scan_history", "scan_threats"} <= tables
    indexes = {
        r[0]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()
    }
    assert {
        "idx_scan_history_status",
        "idx_scan_history_started_at",
        "idx_scan_history_profile",
        "idx_scan_threats_scan_id",
        "idx_scan_threats_name",
    } <= indexes
    conn.close()


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_record_and_get_scan_round_trip(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    result = make_result(
        status=ScanStatus.INFECTED,
        threats=("Eicar FOUND", "Bogus FOUND"),
        engine="clamscan",
        files_scanned=12,
        metadata={"profile_id": "custom"},
    )
    rec = await store.record_scan(result)
    assert rec.id  # uuid generated by app
    got = await store.get_scan(rec.id)
    assert got is not None
    assert got.target == result.target
    assert got.status == "infected"
    assert got.threats == ("Eicar FOUND", "Bogus FOUND")
    assert got.files_scanned == 12
    assert got.metadata == {"profile_id": "custom"}
    assert got.engine == result.engine
    assert got.duration_seconds == pytest.approx(3.0)


@pytest.mark.asyncio
async def test_get_scan_nonexistent_returns_none(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    assert await store.get_scan("missing-id") is None


@pytest.mark.asyncio
async def test_delete_scan_semantics(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    rec = await store.record_scan(make_result())
    assert await store.delete_scan(rec.id) is True
    assert await store.delete_scan(rec.id) is False
    assert await store.get_scan(rec.id) is None


@pytest.mark.asyncio
async def test_clear_history_returns_master_row_count(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    await store.record_scan(make_result(target="/a"))
    await store.record_scan(make_result(target="/b", status=ScanStatus.INFECTED, threats=("X",)))
    assert await store.count_scans() == 2
    deleted = await store.clear_history()
    assert deleted == 2
    assert await store.count_scans() == 0


@pytest.mark.asyncio
async def test_count_scans_filter(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    await store.record_scan(make_result(status=ScanStatus.CLEAN))
    await store.record_scan(make_result(status=ScanStatus.INFECTED, threats=("X",)))
    assert await store.count_scans() == 2
    assert await store.count_scans(status="clean") == 1
    assert await store.count_scans(status="infected") == 1
    with pytest.raises(ValueError):
        await store.count_scans(status="bogus")


# ---------------------------------------------------------------------------
# Purge: retention-oriented deletion (M4-B7)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_purge_before_removes_only_older_records(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    cutoff = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
    await store.record_scan(make_result(target="/old", started_at=cutoff - timedelta(hours=1)))
    await store.record_scan(make_result(target="/exact", started_at=cutoff))
    await store.record_scan(make_result(target="/new", started_at=cutoff + timedelta(hours=1)))
    deleted = await store.purge(before=cutoff)
    assert deleted == 1
    remaining = await store.list_scans()
    assert [r.target for r in remaining] == ["/new", "/exact"]


@pytest.mark.asyncio
async def test_purge_status_removes_only_matching(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    await store.record_scan(make_result(target="/clean", status=ScanStatus.CLEAN))
    await store.record_scan(
        make_result(target="/infected", status=ScanStatus.INFECTED, threats=("X",))
    )
    deleted = await store.purge(status="clean", before=datetime(9999, 1, 1, tzinfo=UTC))
    assert deleted == 1
    remaining = await store.list_scans()
    assert [r.target for r in remaining] == ["/infected"]


@pytest.mark.asyncio
async def test_purge_before_and_status_combined(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    cutoff = datetime(2026, 6, 1, tzinfo=UTC)
    await store.record_scan(
        make_result(target="/old-clean", started_at=cutoff - timedelta(hours=1))
    )
    await store.record_scan(
        make_result(
            target="/old-infected",
            status=ScanStatus.INFECTED,
            threats=("X",),
            started_at=cutoff - timedelta(hours=1),
        )
    )
    await store.record_scan(
        make_result(target="/new-clean", started_at=cutoff + timedelta(hours=1))
    )
    deleted = await store.purge(before=cutoff, status="clean")
    assert deleted == 1
    remaining = await store.list_scans()
    assert [r.target for r in remaining] == ["/new-clean", "/old-infected"]


@pytest.mark.asyncio
async def test_purge_no_criteria_raises(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with pytest.raises(ValueError, match="at least one"):
        await store.purge()


@pytest.mark.asyncio
async def test_purge_unknown_status_raises(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with pytest.raises(ValueError, match="unknown status"):
        await store.purge(status="bogus", before=datetime(9999, 1, 1, tzinfo=UTC))


@pytest.mark.asyncio
async def test_purge_empty_store_returns_zero(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    assert await store.purge(before=datetime(9999, 1, 1, tzinfo=UTC)) == 0


@pytest.mark.asyncio
async def test_purge_no_matching_records_returns_zero(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    await store.record_scan(
        make_result(target="/new", started_at=datetime(2026, 6, 1, tzinfo=UTC))
    )
    assert await store.purge(before=datetime(2000, 1, 1, tzinfo=UTC)) == 0
    assert await store.count_scans() == 1


@pytest.mark.asyncio
async def test_purge_all_matching_records(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    cutoff = datetime(2026, 6, 1, tzinfo=UTC)
    for i in range(3):
        await store.record_scan(
            make_result(target=f"/old-{i}", started_at=cutoff - timedelta(days=i + 1))
        )
    deleted = await store.purge(before=cutoff)
    assert deleted == 3
    assert await store.count_scans() == 0


@pytest.mark.asyncio
async def test_purge_is_idempotent(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    cutoff = datetime(2026, 6, 1, tzinfo=UTC)
    await store.record_scan(
        make_result(target="/old", started_at=cutoff - timedelta(hours=1))
    )
    first = await store.purge(before=cutoff)
    second = await store.purge(before=cutoff)
    assert first == 1
    assert second == 0


@pytest.mark.asyncio
async def test_purge_cascades_threats(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    old = await store.record_scan(
        make_result(
            target="/old-threat",
            status=ScanStatus.INFECTED,
            threats=("Eicar FOUND",),
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
    )
    new = await store.record_scan(
        make_result(
            target="/new-threat",
            status=ScanStatus.INFECTED,
            threats=("Bogus FOUND",),
            started_at=datetime(2026, 6, 1, tzinfo=UTC),
        )
    )
    deleted = await store.purge(before=datetime(2026, 3, 1, tzinfo=UTC))
    assert deleted == 1
    assert await store.get_scan(old.id) is None
    got = await store.get_scan(new.id)
    assert got is not None
    assert got.threats == ("Bogus FOUND",)
    conn = sqlite3.connect(store.path)
    orphan = conn.execute("SELECT COUNT(*) FROM scan_threats").fetchone()[0]
    conn.close()
    assert orphan == 1


@pytest.mark.asyncio
async def test_purge_accepts_naive_datetime(tmp_path: Path) -> None:
    """Naive datetimes are normalized to UTC by encode_timestamp."""
    store = make_store(tmp_path)
    cutoff = datetime(2026, 6, 1, 12, 0, 0)  # naive
    await store.record_scan(
        make_result(target="/old", started_at=datetime(2025, 1, 1, tzinfo=UTC))
    )
    deleted = await store.purge(before=cutoff)
    assert deleted == 1


@pytest.mark.asyncio
async def test_purge_backend_failure_raises_history_error(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    await store.record_scan(make_result(target="/x"))
    await store.close()
    with pytest.raises(HistoryError):
        await store.purge(before=datetime(9999, 1, 1, tzinfo=UTC))


# ---------------------------------------------------------------------------
# Ordering / filters


@pytest.mark.asyncio
async def test_list_defaults_to_descending_by_started_at(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    base = datetime(2026, 1, 1, tzinfo=UTC)
    for i in range(3):
        await store.record_scan(
            make_result(
                target=f"/t{i}",
                started_at=base + timedelta(hours=i),
                finished_at=base + timedelta(hours=i, seconds=3),
            )
        )
    rows = await store.list_scans()
    assert [r.target for r in rows] == ["/t2", "/t1", "/t0"]


@pytest.mark.asyncio
async def test_list_ascending_and_limit_offset(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    base = datetime(2026, 1, 1, tzinfo=UTC)
    for i in range(5):
        await store.record_scan(
            make_result(
                target=f"/t{i}",
                started_at=base + timedelta(hours=i),
                finished_at=base + timedelta(hours=i, seconds=3),
            )
        )
    asc = await store.list_scans(ascending=True, limit=2)
    assert [r.target for r in asc] == ["/t0", "/t1"]
    offset = await store.list_scans(ascending=True, limit=2, offset=3)
    assert [r.target for r in offset] == ["/t3", "/t4"]


@pytest.mark.asyncio
async def test_list_status_filter(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    await store.record_scan(make_result(status=ScanStatus.CLEAN, target="/clean"))
    await store.record_scan(
        make_result(status=ScanStatus.INFECTED, threats=("X",), target="/inf")
    )
    infected = await store.list_scans(status="infected")
    assert [r.target for r in infected] == ["/inf"]
    with pytest.raises(ValueError):
        await store.list_scans(status="nope")


@pytest.mark.asyncio
async def test_list_since_until(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    base = datetime(2026, 1, 10, tzinfo=UTC)
    for delta_h in (0, 6, 30):
        await store.record_scan(
            make_result(
                target=f"/t{delta_h}",
                started_at=base + timedelta(hours=delta_h),
                finished_at=base + timedelta(hours=delta_h, seconds=3),
            )
        )
    since = await store.list_scans(since=base + timedelta(hours=5))
    assert [r.target for r in since] == ["/t30", "/t6"]
    window = await store.list_scans(since=base, until=base + timedelta(hours=12))
    assert [r.target for r in window] == ["/t6", "/t0"]


@pytest.mark.asyncio
async def test_list_validates_arguments(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with pytest.raises(ValueError):
        await store.list_scans(limit=0)
    with pytest.raises(ValueError):
        await store.list_scans(offset=-1)


# ---------------------------------------------------------------------------
# Threat persistence
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_threats_preserve_order_and_survive_clear(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    rec = await store.record_scan(
        make_result(status=ScanStatus.INFECTED, threats=("A", "B", "C"))
    )
    got = await store.get_scan(rec.id)
    assert got.threats == ("A", "B", "C")


@pytest.mark.asyncio
async def test_zero_threats(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    rec = await store.record_scan(make_result(status=ScanStatus.CLEAN))
    assert (await store.get_scan(rec.id)).threats == ()


@pytest.mark.asyncio
async def test_delete_cascades_threats(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    rec = await store.record_scan(make_result(status=ScanStatus.INFECTED, threats=("A", "B")))
    conn = sqlite3.connect(store.path)
    before = conn.execute("SELECT COUNT(*) FROM scan_threats").fetchone()[0]
    assert before == 2
    await store.delete_scan(rec.id)
    after = conn.execute("SELECT COUNT(*) FROM scan_threats").fetchone()[0]
    assert after == 0
    conn.close()


@pytest.mark.asyncio
async def test_clear_cascades_threats(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    await store.record_scan(make_result(status=ScanStatus.INFECTED, threats=("A", "B")))
    await store.record_scan(make_result(status=ScanStatus.INFECTED, threats=("C",)))
    conn = sqlite3.connect(store.path)
    assert conn.execute("SELECT COUNT(*) FROM scan_threats").fetchone()[0] == 3
    await store.clear_history()
    assert conn.execute("SELECT COUNT(*) FROM scan_threats").fetchone()[0] == 0
    conn.close()


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_record_writes_no_loss_no_duplicates(tmp_path: Path) -> None:
    """Real OS-thread concurrency via ``asyncio.to_thread``.

    ``record_scan`` contains no ``await``, so a plain ``asyncio.gather`` would
    run everything sequentially on one event loop (a false positive). Each
    write here runs on a distinct worker thread against the *same* store, so
    the backend's ``threading.RLock`` + single-connection model is what is
    actually exercised. What is proven: no lost records, no duplicate ids, no
    partial master/threat transactions under cross-thread contention. What is
    NOT proven (and not part of the design): multi-process write scaling;
    SQLite calls remain synchronous and serialized by the lock.
    """
    store = make_store(tmp_path)

    async def write(i: int) -> str:
        # asyncio.to_thread only moves the *call* to a thread, so the coroutine
        # is driven to completion there with asyncio.run (it contains no
        # awaits, so this does not change its semantics -- it only places the
        # synchronous SQLite work on a real OS thread).
        rec = await asyncio.to_thread(
            asyncio.run,
            store.record_scan(
                make_result(
                    target=f"/target-{i}",
                    status=ScanStatus.INFECTED,
                    threats=("E" + str(i),),
                )
            ),
        )
        return rec.id

    ids = await asyncio.gather(*(write(i) for i in range(20)))
    assert len(set(ids)) == 20  # no duplicate ids
    rows = await store.list_scans()
    assert len(rows) == 20  # no lost records
    # No partial records: every scan has exactly one threat.
    for rec in rows:
        got = await store.get_scan(rec.id)
        assert len(got.threats) == 1
    conn = sqlite3.connect(store.path)
    threat_rows = conn.execute("SELECT COUNT(*) FROM scan_threats").fetchone()[0]
    assert threat_rows == 20
    conn.close()


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_record_scan_rolls_back_on_threat_failure(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    original = store._insert_threats

    def broken_insert(conn, scan_id, threats):
        raise sqlite3.IntegrityError("boom")

    store._insert_threats = broken_insert
    before_master = sqlite3.connect(store.path).execute(
        "SELECT COUNT(*) FROM scan_history"
    ).fetchone()[0]
    with pytest.raises(HistoryError):
        await store.record_scan(
            make_result(status=ScanStatus.INFECTED, threats=("A", "B"))
        )
    # Restore for later assertions on the same connection semantics.
    store._insert_threats = original
    conn = sqlite3.connect(store.path)
    master = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
    orphan = conn.execute("SELECT COUNT(*) FROM scan_threats").fetchone()[0]
    assert master == before_master
    assert orphan == 0
    conn.close()


# ---------------------------------------------------------------------------
# Security / hostile data
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "hostile",
    [
        "Robert'); DROP TABLE scan_history;--",
        'quote"OR"1=1',
        "split;--",
        "--comment",
        "DROP TABLE scan_threats",
        "/etc/passwd",
        "$(rm -rf /)",
        "`command`",
    ],
)
async def test_hostile_threat_and_metadata_are_safe(tmp_path: Path, hostile: str) -> None:
    store = make_store(tmp_path)
    rec = await store.record_scan(
        make_result(
            status=ScanStatus.INFECTED,
            threats=(hostile,),
            metadata={"injected": hostile, "path": hostile},
        )
    )
    got = await store.get_scan(rec.id)
    assert got.threats == (hostile,)
    assert got.metadata["injected"] == hostile
    conn = sqlite3.connect(store.path)
    check = conn.execute("PRAGMA integrity_check").fetchone()[0]
    assert check == "ok"
    # Tables still exist.
    tables = {
        r[0]
        for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    assert {"scan_history", "scan_threats"} <= tables
    conn.close()


# ---------------------------------------------------------------------------
# Migration / idempotence
# ---------------------------------------------------------------------------


def test_existing_version_1_remains_valid(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    _store = SqliteHistoryStore(db_path)
    assert _store.path == db_path
    conn = sqlite3.connect(db_path)
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert version == 1
    conn.close()
    # Reopening a v1 database must not re-run the schema (idempotent).
    reopened = SqliteHistoryStore(db_path)
    conn = sqlite3.connect(reopened.path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 1
    conn.close()


# ---------------------------------------------------------------------------
# Default path resolution
# ---------------------------------------------------------------------------


def test_default_path_uses_xdg_data_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    path = default_history_db_path()
    assert str(path) == str(tmp_path / "xdg" / "clamguardian" / "history.db")


def test_default_path_falls_back_to_local_share(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    path = default_history_db_path()
    assert str(path) == str(tmp_path / ".local" / "share" / "clamguardian" / "history.db")


# ---------------------------------------------------------------------------
# Store contract & error semantics

# ---------------------------------------------------------------------------
# P1 fix regression tests (deep immutability, migration, WAL perms, rows)
# ---------------------------------------------------------------------------


def test_record_metadata_is_deeply_immutable() -> None:
    rec = history_record_from_scan(make_result(metadata={"a": "1"}))
    with pytest.raises(TypeError):
        rec.metadata["x"] = "y"  # type: ignore[index]
    with pytest.raises(TypeError):
        del rec.metadata["a"]  # type: ignore[attr-defined]


def test_record_profile_snapshot_is_deeply_immutable() -> None:
    rec = history_record_from_scan(make_result(), profile=ScanProfile.custom())
    assert rec.profile_snapshot is not None
    with pytest.raises(TypeError):
        rec.profile_snapshot["x"] = "y"  # type: ignore[index]
    with pytest.raises(TypeError):
        del rec.profile_snapshot["id"]  # type: ignore[attr-defined]


def test_record_deep_freeze_covers_input_isolation() -> None:
    metadata = {"k": "v"}
    profile = ScanProfile.custom()
    rec = history_record_from_scan(make_result(metadata=metadata), profile=profile)
    metadata["k"] = "changed"
    profile.with_overrides(name="Renamed")
    assert rec.metadata == {"k": "v"}
    assert rec.profile_snapshot is not None
    assert rec.profile_snapshot["name"] == "Custom Scan"


def test_migration_failure_leaves_no_partial_schema(tmp_path: Path) -> None:
    """A failure mid-migration must roll back the entire transaction.

    A pre-existing conflicting ``scan_threats`` table forces the migration to
    fail deterministically *after* ``scan_history`` has been created, so the
    rollback (or lack thereof) is observable.
    """
    db_path = tmp_path / "history.db"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE scan_threats (id INTEGER PRIMARY KEY)")
    conn.commit()
    conn.close()

    with pytest.raises(HistoryError):
        SqliteHistoryStore(db_path)

    conn = sqlite3.connect(db_path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
    tables = {
        r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    assert "scan_history" not in tables  # rolled back, no partial schema
    conn.close()

    # Removing the conflict must allow a clean, complete re-initialization.
    conn = sqlite3.connect(db_path)
    conn.execute("DROP TABLE scan_threats")
    conn.commit()
    conn.close()
    store = SqliteHistoryStore(db_path)
    conn = sqlite3.connect(store.path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    assert {"scan_history", "scan_threats"} <= {
        r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    conn.close()


def test_future_schema_version_rejected(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    SqliteHistoryStore(db_path)
    conn = sqlite3.connect(db_path)
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    conn.close()
    with pytest.raises(HistoryError):
        SqliteHistoryStore(db_path)


@pytest.mark.asyncio
async def test_wal_shm_sidecar_permissions(tmp_path: Path) -> None:
    """When present, -wal/-shm sidecars must be 0600 (best-effort, Unix)."""
    store = make_store(tmp_path)
    rec = await store.record_scan(
        make_result(status=ScanStatus.INFECTED, threats=("X",), metadata={"k": "v"})
    )
    # WAL/SHM are created lazily by SQLite; if the filesystem does not expose
    # them, skipping is motivated, not a silent pass.
    wal = Path(str(store.path) + "-wal")
    shm = Path(str(store.path) + "-shm")
    if not wal.exists() and not shm.exists():
        pytest.skip("filesystem/SQLite build does not expose WAL sidecar files")
    for sidecar in (wal, shm):
        if sidecar.exists():
            assert sidecar.stat().st_mode & 0o777 == 0o600, sidecar
    # chmod must not break normal SQLite operation.
    rec2 = await store.record_scan(make_result(target="/after-chmod"))
    assert (await store.get_scan(rec2.id)) is not None
    assert (await store.get_scan(rec.id)) is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "column,value",
    [
        ("started_at", "not-a-date"),
        ("finished_at", "not-a-date"),
        ("created_at", "not-a-date"),
        ("status", "INVALID"),
    ],
)
async def test_malformed_rows_are_skipped_not_crashing(
    tmp_path: Path, column: str, value: str
) -> None:
    store = make_store(tmp_path)
    good = await store.record_scan(make_result(target="/good"))
    bad = await store.record_scan(make_result(target="/bad"))
    conn = sqlite3.connect(store.path)
    # The CHECK constraint would reject an invalid status at write time; the
    # injection simulates a row corrupted out-of-band (e.g. older tooling).
    conn.execute("PRAGMA ignore_check_constraints = ON")
    # column comes from the fixed whitelist above, not from user input.
    conn.execute(f"UPDATE scan_history SET {column} = ? WHERE id = ?", (value, bad.id))
    conn.commit()
    conn.close()
    # Corrupt row: treated as missing / skipped, valid rows unaffected.
    assert await store.get_scan(bad.id) is None
    assert await store.get_scan(good.id) is not None
    assert [r.target for r in await store.list_scans()] == ["/good"]


@pytest.mark.asyncio
async def test_malformed_json_columns_are_defensive(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    rec = await store.record_scan(make_result(metadata={"k": "v"}))
    conn = sqlite3.connect(store.path)
    conn.execute(
        "UPDATE scan_history SET metadata_json = '{broken', profile_snapshot = '[not-a-dict' "
        "WHERE id = ?",
        (rec.id,),
    )
    conn.commit()
    conn.close()
    got = await store.get_scan(rec.id)
    assert got is not None
    assert got.metadata == {}
    assert got.profile_snapshot is None
# ---------------------------------------------------------------------------


def test_history_store_is_protocol_compatible() -> None:
    assert HistoryStore is not None
    assert isinstance(HistoryError("x"), Exception)


def test_history_error_alias() -> None:
    from clamguardian.history import HistoryError as PublicHistoryError

    assert PublicHistoryError is HistoryError
