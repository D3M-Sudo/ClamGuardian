"""Tests for the desktop quarantine key manager path handling.

Regression coverage for the startup crash where the history database *file*
path was handed to :class:`QuarantineKeyManager`, which then tried to
``mkdir`` on it and raised ``FileExistsError``.
"""

from __future__ import annotations

import asyncio
import sys
import types
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


class _FakeSchema:
    created: tuple[object, ...] | None = None

    @classmethod
    def new(cls, name, flags, attributes):
        cls.created = (name, flags, attributes)
        return "fake-schema"


class _FakeSecret:
    """Minimal stand-in for ``gi.repository.Secret`` (API-shape assertions)."""

    Schema = _FakeSchema
    COLLECTION_DEFAULT = "default"
    stored_password: str | None = None
    lookup_call: tuple[object, ...] | None = None
    store_call: tuple[object, ...] | None = None

    class SchemaFlags:
        NONE = 0

    class SchemaAttributeType:
        STRING = "string"

    @classmethod
    def password_lookup_sync(cls, schema, attributes, cancellable):
        cls.lookup_call = (schema, attributes, cancellable)
        return cls.stored_password

    @classmethod
    def password_store_sync(cls, schema, attributes, collection, label, password, cancellable):
        cls.store_call = (schema, attributes, collection, label, password, cancellable)
        cls.stored_password = password
        return True


def _install_fake_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    gi_module = types.ModuleType("gi")
    gi_module.require_version = lambda name, version: None  # type: ignore[attr-defined]
    repository = types.ModuleType("gi.repository")
    repository.Secret = _FakeSecret  # type: ignore[attr-defined]
    gi_module.repository = repository  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "gi", gi_module)
    monkeypatch.setitem(sys.modules, "gi.repository", repository)


def test_secret_service_receives_schema_attributes_and_six_arguments(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install_fake_secret(monkeypatch)
    _FakeSecret.stored_password = None
    _FakeSecret.store_call = None
    manager = QuarantineKeyManager(tmp_path / "quarantine")

    key = manager.load_or_create()

    assert _FakeSecret.store_call is not None
    schema, attributes, collection, label, password, cancellable = _FakeSecret.store_call
    assert schema == "fake-schema"
    assert attributes == {"purpose": "quarantine-key"}
    assert collection == "default"
    assert label
    assert password == key.hex()
    assert cancellable is None
    assert not (manager.directory / "quarantine-key").exists()


def test_secret_service_lookup_returns_existing_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install_fake_secret(monkeypatch)
    key = bytes(range(32))
    _FakeSecret.stored_password = key.hex()
    manager = QuarantineKeyManager(tmp_path / "quarantine")

    assert manager.load_or_create() == key
    assert _FakeSecret.lookup_call is not None
    assert _FakeSecret.lookup_call[1] == {"purpose": "quarantine-key"}


def test_key_file_is_owner_only_and_has_no_temp_leftovers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    manager = QuarantineKeyManager(tmp_path / "quarantine")
    monkeypatch.setattr(manager, "_load_secret_service", lambda: None)
    monkeypatch.setattr(manager, "_store_secret_service", lambda key: False)

    key = manager.load_or_create()

    path = manager.directory / "quarantine-key"
    assert path.read_text(encoding="ascii") == key.hex()
    assert path.stat().st_mode & 0o777 == 0o600
    assert list(manager.directory.glob(".quarantine-key.*")) == []


def test_corrupt_key_file_refuses_to_rotate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    manager = QuarantineKeyManager(tmp_path / "quarantine")
    monkeypatch.setattr(manager, "_load_secret_service", lambda: None)
    manager._store_file(bytes(range(32)))
    (manager.directory / "quarantine-key").write_text("deadbeef", encoding="ascii")

    with pytest.raises(ValueError, match="corrupt"):
        manager.load_or_create()

