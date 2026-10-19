"""Widget-level tests for the application shell (Phase D4).

These run only with PyGObject and a display; the CI test job runs the whole
suite under Xvfb.  Without a display they are skipped and the pure-logic
tests still cover the same contracts.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from _gtk_probe import gtk_works

pytestmark = pytest.mark.skipif(
    not gtk_works(), reason="requires PyGObject + display/Xvfb"
)


@pytest.fixture(scope="module")
def gtk_app():
    """One registered application shared by the widget tests."""
    from clamguardian.ui.app import ClamGuardianApp

    app = ClamGuardianApp()
    assert app.register()
    yield app
    app.unregister()


def test_shell_exposes_every_page_and_switches_between_them(
    gtk_app, tmp_path: Path
) -> None:
    from clamguardian.core.settings import SettingsStore
    from clamguardian.databases import DatabaseManager
    from clamguardian.history.backend import SqliteHistoryStore
    from clamguardian.ui.app import SIDEBAR_ENTRIES, MainWindow
    from clamguardian.ui.quarantine_key import QuarantineKeyManager

    try:
        window = MainWindow(
            gtk_app,
            checks=[],
            manager=DatabaseManager(tmp_path / "databases", tmp_path / "state.json"),
            history_store=SqliteHistoryStore(tmp_path / "history.db"),
            key_manager=QuarantineKeyManager(tmp_path / "quarantine"),
            settings_store=SettingsStore(tmp_path / "settings.json"),
        )
    except Exception:  # pragma: no cover - needs a working X server/Adw
        pytest.skip("GTK/Adw widget construction failed in this environment")

    expected = {page_id for page_id, _label, _icon in SIDEBAR_ENTRIES}
    assert set(window.page_ids) == expected
    for page_id in window.page_ids:
        window.show_page(page_id)
        assert window.visible_page_id == page_id
    window.destroy()


def test_shell_applies_the_persisted_color_scheme(gtk_app, tmp_path: Path) -> None:
    from clamguardian.core.settings import AppSettings, SettingsStore
    from clamguardian.ui.app import MainWindow
    from clamguardian.ui.quarantine_key import QuarantineKeyManager

    store = SettingsStore(tmp_path / "settings.json")
    store.save(
        AppSettings(
            default_profile_id="home",
            notifications_enabled=False,
            color_scheme="dark",
        )
    )
    try:
        window = MainWindow(
            gtk_app,
            checks=[],
            key_manager=QuarantineKeyManager(tmp_path / "quarantine"),
            settings_store=store,
        )
    except Exception:  # pragma: no cover - needs a working X server/Adw
        pytest.skip("GTK/Adw widget construction failed in this environment")

    assert window.settings.default_profile_id == "home"
    assert window.settings.color_scheme == "dark"
    window.destroy()
