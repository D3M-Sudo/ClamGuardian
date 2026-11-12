#!/usr/bin/env python3
"""Construct the complete GTK UI without entering the application event loop."""

from __future__ import annotations

import tempfile
from pathlib import Path

from clamguardian.core.settings import AppSettings, SettingsStore
from clamguardian.databases import DatabaseManager
from clamguardian.history.backend import SqliteHistoryStore
from clamguardian.ui import build_database_navigation
from clamguardian.ui.about import build_about_dialog
from clamguardian.ui.app import SIDEBAR_ENTRIES, ClamGuardianApp, MainWindow
from clamguardian.ui.controller import ShieldTaskController
from clamguardian.ui.diagnostics_page import DiagnosticsPage
from clamguardian.ui.quarantine_key import QuarantineKeyManager
from clamguardian.ui.scan_page import GTK_AVAILABLE, ScanPage
from clamguardian.ui.theme import load_css

if not GTK_AVAILABLE:
    raise SystemExit("GTK smoke test requires PyGObject and GTK4/Libadwaita")

with tempfile.TemporaryDirectory(prefix="clamguardian-gtk-smoke-") as temporary:
    root = Path(temporary)
    manager = DatabaseManager(root / "databases", root / "state.json")
    build_database_navigation(manager)

    # register() emits GApplication::startup before application windows exist.
    app = ClamGuardianApp()
    if not app.register():
        raise SystemExit("GApplication registration failed")

    settings_store = SettingsStore(root / "settings.json")
    settings_store.save(
        AppSettings(
            default_profile_id="home",
            notifications_enabled=False,
            color_scheme="dark",
        )
    )
    window = MainWindow(
        app,
        checks=[],
        manager=manager,
        controller=ShieldTaskController(),
        history_store=SqliteHistoryStore(root / "history.db"),
        key_manager=QuarantineKeyManager(root / "quarantine"),
        settings_store=settings_store,
    )

    assert window.toast_overlay is not None
    assert load_css(), "application stylesheet must load"
    assert window.settings.default_profile_id == "home"

    expected_pages = {page_id for page_id, _label, _icon in SIDEBAR_ENTRIES}
    assert set(window.page_ids) == expected_pages
    for page_id in window.page_ids:
        window.show_page(page_id)
        assert window.visible_page_id == page_id

    diagnostics = DiagnosticsPage()
    assert diagnostics.checks, "diagnostics page must render at least one check"
    scan_page = ScanPage(ShieldTaskController())
    assert scan_page.root is not None
    assert not scan_page.in_flight
    assert build_about_dialog() is not None

    print("CLAMGUARDIAN_GTK_SMOKE_OK")
