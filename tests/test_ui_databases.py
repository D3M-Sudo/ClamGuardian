"""Headless tests for the GTK4/Libadwaita database UI layer."""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import pytest

from clamguardian.databases.manager import DatabaseManager, DatabaseUpdateError
from clamguardian.databases.models import (
    DatabaseArtifact,
    DatabaseSource,
    DatabaseStatus,
    InstalledDatabase,
)
from clamguardian.ui import GTK_AVAILABLE, ThirdPartyDatabasesPage
from clamguardian.ui.database_pages import STATUS_LABELS, run_async


class FakeProvider:
    def __init__(self, content: bytes = b"good", fail: bool = False) -> None:
        self.content, self.fail = content, fail

    async def download(self, source, destination):
        if self.fail:
            raise RuntimeError("network unavailable")
        destination.mkdir(parents=True, exist_ok=True)
        path = destination / source.artifacts[0].filename
        path.write_bytes(self.content)
        yield path


def make_source(source_id: str = "thirdparty") -> DatabaseSource:
    return DatabaseSource(
        source_id,
        "Malware DB",
        "Community ClamAV signatures",
        (
            DatabaseArtifact(
                f"{source_id}.cvd",
                "https://example.invalid/db.cvd",
                hashlib.sha256(b"good").hexdigest(),
            ),
        ),
    )


def make_manager(tmp_path: Path) -> DatabaseManager:
    return DatabaseManager(tmp_path / "db", tmp_path / "state.json", provider=FakeProvider())


def test_ui_imports_are_headless_safe() -> None:
    """The UI names must be importable without a display or GTK runtime."""
    assert isinstance(GTK_AVAILABLE, bool)
    if not GTK_AVAILABLE:
        with pytest.raises(RuntimeError, match="not available"):
            ThirdPartyDatabasesPage(None)


def test_status_mapping_covers_all_states() -> None:
    assert set(STATUS_LABELS) == set(DatabaseStatus)
    assert STATUS_LABELS[DatabaseStatus.AVAILABLE] == "Available"
    assert STATUS_LABELS[DatabaseStatus.INSTALLED] == "Installed"
    assert STATUS_LABELS[DatabaseStatus.DISABLED] == "Disabled"
    assert STATUS_LABELS[DatabaseStatus.UPDATING] == "Updating…"
    assert STATUS_LABELS[DatabaseStatus.ERROR] == "Update error"


def test_status_enum_values() -> None:
    assert DatabaseStatus.AVAILABLE.value == "available"
    assert DatabaseStatus.INSTALLED.value == "installed"
    assert DatabaseStatus.DISABLED.value == "disabled"
    assert DatabaseStatus.UPDATING.value == "updating"
    assert DatabaseStatus.ERROR.value == "error"


def test_add_source_renders_available_to_ui(tmp_path: Path) -> None:
    """manager.add_source() makes the source visible through manager.sources."""
    manager = make_manager(tmp_path)
    assert manager.sources == ()
    manager.add_source(make_source())
    assert len(manager.sources) == 1
    assert manager.status("thirdparty") == InstalledDatabase(
        manager.sources[0], DatabaseStatus.AVAILABLE
    )


def test_remove_source_drops_it_from_manager(tmp_path: Path) -> None:
    manager = make_manager(tmp_path)
    manager.add_source(make_source())
    manager.remove_source("thirdparty")
    assert manager.sources == ()
    with pytest.raises(KeyError):
        manager.status("thirdparty")


def test_duplicate_source_id_is_rejected(tmp_path: Path) -> None:
    manager = make_manager(tmp_path)
    manager.add_source(make_source())
    with pytest.raises(ValueError, match="already exists"):
        manager.add_source(make_source())


def test_update_transitions_to_installed(tmp_path: Path) -> None:
    manager = make_manager(tmp_path)
    manager.add_source(make_source())
    result = asyncio.run(manager.update("thirdparty"))
    assert result.status == DatabaseStatus.INSTALLED


def test_failed_update_reports_error_and_keeps_previous(tmp_path: Path) -> None:
    manager = make_manager(tmp_path)
    manager.add_source(make_source())
    asyncio.run(manager.update("thirdparty"))
    manager.provider = FakeProvider(fail=True)
    with pytest.raises(DatabaseUpdateError):
        asyncio.run(manager.update("thirdparty"))
    status = manager.status("thirdparty")
    assert status.status == DatabaseStatus.ERROR
    assert (tmp_path / "db" / "thirdparty.cvd").read_bytes() == b"good"


def test_validation_rejects_insecure_urls_and_filenames() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        DatabaseSource(
            "x", "X", "desc", (DatabaseArtifact("db.cvd", "http://example.invalid/db.cvd"),)
        )
    with pytest.raises(ValueError, match="Unsafe"):
        DatabaseSource(
            "x", "X", "desc", (DatabaseArtifact("../evil.cvd", "https://example.invalid/db.cvd"),)
        )


def test_validation_rejects_invalid_sha256_and_empty_fields() -> None:
    with pytest.raises(ValueError, match="SHA-256"):
        DatabaseSource(
            "x",
            "X",
            "desc",
            (DatabaseArtifact("db.cvd", "https://example.invalid/db.cvd", "nothex"),),
        )
    with pytest.raises(ValueError, match="empty"):
        DatabaseSource(
            "  ", "X", "desc", (DatabaseArtifact("db.cvd", "https://example.invalid/db.cvd"),)
        )
    with pytest.raises(ValueError, match="at least one artifact"):
        DatabaseSource("x", "X", "desc", ())


def test_state_persistence_round_trip(tmp_path: Path) -> None:
    manager = make_manager(tmp_path)
    manager.add_source(make_source())
    asyncio.run(manager.update("thirdparty"))
    restored = DatabaseManager(tmp_path / "db", tmp_path / "state.json", provider=FakeProvider())
    assert restored.sources[0].name == "Malware DB"
    assert restored.status("thirdparty").status == DatabaseStatus.INSTALLED


def test_run_async_worker_thread_fallback() -> None:
    """Without a running loop the coroutine runs and the callback receives its result."""
    import threading

    results: list[object] = []
    done = threading.Event()

    async def _value() -> int:
        await asyncio.sleep(0)
        return 42

    def _collect(result: object, error: Exception | None) -> None:
        results.append((result, error))
        done.set()

    run_async(_value(), _collect)
    assert done.wait(timeout=5)
    assert results == [(42, None)]
