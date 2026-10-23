"""Tests for the desktop settings store (Phase D4).

The store is stdlib-only, so these tests run on every environment.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from clamguardian.core.settings import (
    DEFAULT_PROFILE_ID,
    AppSettings,
    SettingsStore,
    default_settings_path,
)


def test_defaults_are_sane() -> None:
    settings = AppSettings()
    assert settings.default_profile_id == DEFAULT_PROFILE_ID
    assert settings.notifications_enabled is True
    assert settings.color_scheme == "system"
    # "quick" is a real registered profile and is *not* list index 0.
    assert settings.normalized() == settings


def test_missing_file_returns_defaults(tmp_path: Path) -> None:
    store = SettingsStore(tmp_path / "missing.json")
    assert store.load() == AppSettings()


def test_round_trip(tmp_path: Path) -> None:
    store = SettingsStore(tmp_path / "settings.json")
    saved = store.save(
        AppSettings(
            default_profile_id="home",
            notifications_enabled=False,
            color_scheme="dark",
        )
    )
    assert saved.default_profile_id == "home"
    assert store.load() == saved


def test_saved_file_is_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    SettingsStore(path).save(AppSettings())
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600


def test_atomic_write_leaves_no_temporary_file(tmp_path: Path) -> None:
    store = SettingsStore(tmp_path / "settings.json")
    store.save(AppSettings())
    assert [entry.name for entry in tmp_path.iterdir()] == ["settings.json"]


def test_corrupt_json_degrades_to_defaults(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text("{not json", encoding="utf-8")
    assert SettingsStore(path).load() == AppSettings()


def test_non_object_json_degrades_to_defaults(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text("[]", encoding="utf-8")
    assert SettingsStore(path).load() == AppSettings()


def test_unknown_profile_falls_back_to_default(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"default_profile_id": "nope"}), encoding="utf-8")
    assert SettingsStore(path).load().default_profile_id == DEFAULT_PROFILE_ID


def test_invalid_color_scheme_falls_back_to_system(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"color_scheme": "neon"}), encoding="utf-8")
    assert SettingsStore(path).load().color_scheme == "system"


def test_wrong_types_in_file_are_ignored(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text(
        json.dumps(
            {
                "default_profile_id": 42,
                "notifications_enabled": "yes",
                "color_scheme": None,
            }
        ),
        encoding="utf-8",
    )
    assert SettingsStore(path).load() == AppSettings()


def test_unknown_keys_are_ignored(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text(
        json.dumps({"default_profile_id": "full", "future_option": True}),
        encoding="utf-8",
    )
    settings = SettingsStore(path).load()
    assert settings.default_profile_id == "full"


def test_save_normalizes_before_persisting(tmp_path: Path) -> None:
    store = SettingsStore(tmp_path / "settings.json")
    saved = store.save(AppSettings(default_profile_id="not-a-profile"))
    assert saved.default_profile_id == DEFAULT_PROFILE_ID
    assert store.load().default_profile_id == DEFAULT_PROFILE_ID


def test_default_path_is_next_to_history_db(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert default_settings_path() == tmp_path / "clamguardian" / "settings.json"
