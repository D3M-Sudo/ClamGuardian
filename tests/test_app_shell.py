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
    """One registered application shared by the widget tests.

    PyGObject does not expose ``Gio.Application.unregister()``, so the
    application lives for the duration of the pytest process; no other test
    module registers a ``ClamGuardianApp``.
    """
    from clamguardian.ui.app import ClamGuardianApp

    app = ClamGuardianApp()
    assert app.register()
    yield app


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


@pytest.mark.parametrize("service_loop_state", ["missing", "closed"])
def test_shutdown_always_closes_intelligence_worker(
    gtk_app, service_loop_state: str
) -> None:
    from types import SimpleNamespace
    from unittest.mock import Mock

    app = gtk_app
    intelligence_service = Mock()
    app._window = SimpleNamespace(_intelligence_service=intelligence_service)
    service_loop = None
    if service_loop_state == "closed":
        import asyncio

        service_loop = asyncio.new_event_loop()
        service_loop.close()
    app._service_loop = service_loop

    app._on_shutdown(app)

    intelligence_service.close.assert_called_once_with(timeout=8)


def test_shutdown_cancels_ui_scans_when_service_loop_never_started(gtk_app) -> None:
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock

    app = gtk_app
    runner = SimpleNamespace(cancel_all=AsyncMock())
    intelligence_service = Mock()
    app._window = SimpleNamespace(
        _intelligence_service=intelligence_service,
        _scan_controller=SimpleNamespace(_runner=runner),
    )
    app._service_loop = None
    app._service_runner = None

    app._on_shutdown(app)

    runner.cancel_all.assert_awaited_once()
    intelligence_service.close.assert_called_once_with(timeout=8)
