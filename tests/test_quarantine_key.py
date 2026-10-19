"""Tests for the desktop quarantine key manager path handling.

Regression coverage for the startup crash where the history database *file*
path was handed to :class:`QuarantineKeyManager`, which then tried to
``mkdir`` on it and raised ``FileExistsError``.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from clamguardian.history.backend import SqliteHistoryStore, default_history_db_path
from clamguardian.ui.quarantine_key import QuarantineKeyManager, default_quarantine_dir


def test_default_quarantine_dir_is_sibling_of_history_db(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))

    history_db = default_history_db_path()
    quarantine_dir = default_quarantine_dir()

    assert history_db == tmp_path / "clamguardian" / "history.db"
    assert quarantine_dir == tmp_path / "clamguardian" / "quarantine"
    assert history_db.parent == quarantine_dir.parent


def test_key_manager_starts_with_existing_history_db(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The key manager must never treat ``history.db`` as its directory."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))

    # A previous run already created the history database in app-data.
    store = SqliteHistoryStore(default_history_db_path())
    asyncio.run(store.close())

    manager = QuarantineKeyManager(default_quarantine_dir())
    key = manager.load_or_create()

    assert manager.directory.is_dir()
    assert manager.directory.name == "quarantine"
    assert len(key) == 32
