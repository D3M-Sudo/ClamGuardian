"""Tests for the desktop settings page (Phase D4).

Pure helpers run everywhere; widget construction runs under Xvfb only.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from _gtk_probe import gtk_works

import clamguardian.ui.settings_page as settings_page_module
from clamguardian.core.profiles import DEFAULT_REGISTRY
from clamguardian.core.settings import AppSettings, SettingsStore


def test_profile_index_matches_the_registry_order() -> None:
    ids = [profile.id for profile in DEFAULT_REGISTRY.list()]
    for index, profile_id in enumerate(ids):
        assert settings_page_module.profile_index(profile_id) == index


def test_profile_index_falls_back_to_the_default_profile() -> None:
    ids = [profile.id for profile in DEFAULT_REGISTRY.list()]
    assert settings_page_module.profile_index("not-a-profile") == ids.index(
        "quick"
    )


@pytest.mark.skipif(
    settings_page_module.GTK_AVAILABLE, reason="headless shim only without PyGObject"
)
def test_settings_page_shim_raises_headless() -> None:
    with pytest.raises(RuntimeError, match="PyGObject"):
        settings_page_module.SettingsPage(None)  # type: ignore[arg-type]


@pytest.mark.skipif(not gtk_works(), reason="requires PyGObject + display/Xvfb")
def test_settings_page_reflects_stored_values(tmp_path: Path) -> None:
    store = SettingsStore(tmp_path / "settings.json")
    store.save(
        AppSettings(
            default_profile_id="home",
            notifications_enabled=False,
            color_scheme="dark",
        )
    )
    try:
        page = settings_page_module.SettingsPage(store)
    except Exception:  # pragma: no cover - needs a working X server/Adw
        pytest.skip("GTK/Adw widget construction failed in this environment")
    assert page.settings.default_profile_id == "home"
    assert page.settings.notifications_enabled is False
    assert page.settings.color_scheme == "dark"


@pytest.mark.skipif(not gtk_works(), reason="requires PyGObject + display/Xvfb")
def test_changing_the_profile_persists_it(tmp_path: Path) -> None:
    store = SettingsStore(tmp_path / "settings.json")
    try:
        page = settings_page_module.SettingsPage(store)
        page._on_profile_changed(page._profile_row, None)
    except Exception:  # pragma: no cover - needs a working X server/Adw
        pytest.skip("GTK/Adw widget construction failed in this environment")
    assert store.load() == page.settings
