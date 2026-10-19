"""GTK4/Libadwaita application shell for ClamGuardian.

`ClamGuardianApp` owns a single `MainWindow` built around
`Adw.NavigationSplitView`, in the layout of the approved desktop plan
(Malwarebytes-style sidebar mapped to Libadwaita): Scan, History,
Quarantine, Databases, Diagnostics and Settings.

The shell owns the window chrome (header bars, menu, About dialog), loads the
application stylesheet, applies the persisted colour scheme and keeps pages
fresh when they are shown.  At startup it runs the Core dependency checks
and, when a critical dependency is missing, switches to the Diagnostics page
and presents a blocking dialog with the remedy.

The module is import-safe on headless systems without PyGObject, following
the shim pattern of :mod:`clamguardian.ui.database_pages`.
"""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Sequence
from pathlib import Path

from ..core.base import ScanResult
from ..core.diagnostics import CheckResult, critical_missing, run_dependency_checks
from ..core.quarantine import QuarantineEntry, QuarantineVault
from ..core.settings import AppSettings, SettingsStore
from ..history.backend import SqliteHistoryStore, default_history_db_path
from .controller import ShieldTaskController
from .database_pages import GTK_AVAILABLE
from .diagnostics_page import DiagnosticsPage
from .history_page import HistoryPage
from .notifications import notify_scan_result, withdraw_scan_notification
from .quarantine_key import QuarantineKeyManager, default_quarantine_dir
from .quarantine_page import QuarantinePage
from .scan_page import ScanPage
from .settings_page import SettingsPage
from .theme import apply_color_scheme, load_css

if GTK_AVAILABLE:  # pragma: no cover - exercised only on systems with PyGObject
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gio, GLib, Gtk

    from ..databases import DatabaseManager
    from .about import build_about_dialog
    from .database_pages import AntivirusDatabasesPage
    from .dialogs import alert_dialog

    #: Sidebar entries as ``(stack id, label, icon)``; page construction for
    #: each entry lives in :meth:`MainWindow._build_page`.
    SIDEBAR_ENTRIES: tuple[tuple[str, str, str], ...] = (
        ("scan", "Scan", "system-run-symbolic"),
        ("history", "History", "document-open-recent-symbolic"),
        ("quarantine", "Quarantine", "channel-secure-symbolic"),
        ("databases", "Databases", "database-symbolic"),
        ("diagnostics", "Diagnostics", "emblem-system-symbolic"),
        ("settings", "Settings", "preferences-system-symbolic"),
    )

    SIDEBAR_LABELS: dict[str, str] = {
        page_id: label for page_id, label, _icon in SIDEBAR_ENTRIES
    }

    def _default_database_manager() -> DatabaseManager:
        """Build the production DatabaseManager on the app data directory.

        Inside the Flatpak sandbox `GLib.get_user_data_dir()` points at the
        app-data dir granted by `--filesystem=xdg-data/clamguardian:create`;
        outside it resolves to the user's XDG data dir. Paths only — the
        manager itself never invents locations at import time.
        """
        data_dir = Path(GLib.get_user_data_dir()) / "clamguardian"
        return DatabaseManager(
            database_dir=data_dir / "databases",
            state_file=data_dir / "databases.json",
        )

    class MainWindow(Adw.ApplicationWindow):
        """Main window: sidebar navigation, page stack and window chrome."""

        def __init__(
            self,
            application: Adw.Application,
            *,
            checks: Sequence[CheckResult] | None = None,
            manager: DatabaseManager | None = None,
            controller: ShieldTaskController | None = None,
            history_store: SqliteHistoryStore | None = None,
            key_manager: QuarantineKeyManager | None = None,
            settings_store: SettingsStore | None = None,
        ) -> None:
            super().__init__(
                application=application,
                title="ClamGuardian",
                default_width=1100,
                default_height=720,
            )
            self._checks: list[CheckResult] = list(
                checks if checks is not None else run_dependency_checks()
            )
            self._scan_controller = (
                controller if controller is not None else ShieldTaskController()
            )
            self._history_store = (
                history_store
                if history_store is not None
                else SqliteHistoryStore(default_history_db_path())
            )
            self._key_manager = (
                key_manager
                if key_manager is not None
                else QuarantineKeyManager(default_quarantine_dir())
            )
            self._settings_store = (
                settings_store if settings_store is not None else SettingsStore()
            )
            self._settings = self._settings_store.load()
            self._vault = QuarantineVault(
                self._key_manager.directory,
                self._key_manager.load_or_create(),
            )
            self._scan_page: ScanPage | None = None
            self._history_page: HistoryPage | None = None
            self._quarantine_page: QuarantinePage | None = None
            self._suppress_selection = False

            self._stack = Gtk.Stack(vexpand=True, hexpand=True)
            self._pages: dict[str, Gtk.Widget] = {}
            for page_id, _label, _icon in SIDEBAR_ENTRIES:
                self._stack.add_named(self._build_page(page_id, manager), page_id)

            self._toast_overlay = Adw.ToastOverlay(child=self._stack)

            sidebar = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
            sidebar.add_css_class("navigation-sidebar")
            self._sidebar = sidebar
            self._sidebar_rows: dict[str, Gtk.ListBoxRow] = {}
            for index, (page_id, label, icon) in enumerate(SIDEBAR_ENTRIES):
                row = Gtk.ListBoxRow()
                content = Gtk.Box(
                    spacing=12,
                    margin_start=12,
                    margin_end=12,
                    margin_top=8,
                    margin_bottom=8,
                )
                content.append(Gtk.Image(icon_name=icon))
                content.append(Gtk.Label(label=label, xalign=0))
                row.set_child(content)
                row.page_id = page_id
                sidebar.append(row)
                self._sidebar_rows[page_id] = row
                if index == 0:
                    sidebar.select_row(row)
            sidebar.connect("row-selected", self._on_sidebar_selected)

            self._window_title = Adw.WindowTitle(title="Scan", subtitle="ClamGuardian")

            content_header = Adw.HeaderBar()
            content_header.set_title_widget(self._window_title)
            menu_button = Gtk.MenuButton(icon_name="open-menu-symbolic")
            menu_button.set_tooltip_text("Main menu")
            menu_button.set_menu_model(self._build_menu())
            content_header.pack_end(menu_button)

            content_toolbar = Adw.ToolbarView()
            content_toolbar.add_top_bar(content_header)
            content_toolbar.set_content(self._toast_overlay)

            sidebar_header = Adw.HeaderBar()
            sidebar_header.set_title_widget(
                Adw.WindowTitle(title="ClamGuardian", subtitle="Antivirus")
            )
            sidebar_toolbar = Adw.ToolbarView()
            sidebar_toolbar.add_top_bar(sidebar_header)
            sidebar_toolbar.set_content(sidebar)

            split = Adw.NavigationSplitView()
            split.set_sidebar(
                Adw.NavigationPage(title="ClamGuardian", child=sidebar_toolbar)
            )
            split.set_content(
                Adw.NavigationPage(title="ClamGuardian", child=content_toolbar)
            )
            self.set_content(split)

            self.connect("notify::is-active", self._on_active_changed)

        # -- public API ----------------------------------------------------

        @property
        def toast_overlay(self) -> Adw.ToastOverlay:
            return self._toast_overlay

        @property
        def page_ids(self) -> tuple[str, ...]:
            """The ids of every page embedded in the stack."""
            return tuple(self._pages)

        @property
        def visible_page_id(self) -> str | None:
            """The id of the page currently shown, if any."""
            return self._stack.get_visible_child_name()

        @property
        def settings(self) -> AppSettings:
            """The currently applied settings."""
            return self._settings

        def show_page(self, page_id: str) -> None:
            """Switch the content stack and the sidebar selection to *page_id*."""
            if page_id not in self._pages:
                return
            row = self._sidebar_rows[page_id]
            if self._sidebar.get_selected_row() is not row:
                self._suppress_selection = True
                try:
                    self._sidebar.select_row(row)
                finally:
                    self._suppress_selection = False
            self._show_page_content(page_id)

        def _show_page_content(self, page_id: str) -> None:
            self._stack.set_visible_child_name(page_id)
            self._window_title.set_title(SIDEBAR_LABELS.get(page_id, "ClamGuardian"))
            page = self._pages[page_id]
            refresh = getattr(page, "refresh", None)
            if callable(refresh):
                refresh()

        def show_diagnostics(self, missing: Sequence[CheckResult]) -> None:
            """Surface the Diagnostics page and a blocking alert for *missing*."""
            self.show_page("diagnostics")
            # Dialog bodies may render Pango markup: escape dynamic text.
            names = "\n".join(
                f"• {GLib.markup_escape_text(result.label)}: "
                f"{GLib.markup_escape_text(result.detail)}"
                for result in missing
            )
            remedies = "\n".join(
                GLib.markup_escape_text(command)
                for result in missing
                for command in list(result.remedies.values())[:1]
            )
            body = f"{names}\n\nSuggested commands:\n{remedies}" if remedies else names
            dialog = alert_dialog("ClamAV is not ready to scan", body)
            dialog.present(self)

        def show_about(self) -> None:
            """Present the About dialog."""
            dialog = build_about_dialog()
            try:
                dialog.present(self)
            except TypeError:  # pragma: no cover - Gtk.AboutDialog fallback
                dialog.present()

        # -- internals -----------------------------------------------------

        def _build_menu(self) -> Gio.Menu:
            menu = Gio.Menu()
            menu.append("About ClamGuardian", "app.about")
            menu.append("Quit", "app.quit")
            return menu

        def _on_sidebar_selected(
            self, _sidebar: Gtk.ListBox, row: Gtk.ListBoxRow | None
        ) -> None:
            if row is None or self._suppress_selection:
                return
            page_id = getattr(row, "page_id", None)
            if page_id:
                self._show_page_content(page_id)

        def _on_settings_changed(self, settings: AppSettings) -> None:
            self._settings = settings
            if self._scan_page is not None:
                self._scan_page.set_default_profile(settings.default_profile_id)
            apply_color_scheme(settings.color_scheme)

        def _on_active_changed(self, window: Gtk.Window, _pspec: object) -> None:
            if window.is_active():
                withdraw_scan_notification(self.get_application())

        async def _store_scan_result(self, result: ScanResult) -> None:
            """Persist *result* to the history store off the GTK loop."""
            await self._history_store.record_scan(result)
            GLib.idle_add(self._after_scan_recorded, result)

        def _after_scan_recorded(self, result: ScanResult) -> bool:
            if self.visible_page_id == "history" and self._history_page is not None:
                self._history_page.refresh()
            if self._settings.notifications_enabled and not self.is_active():
                notify_scan_result(self.get_application(), result)
            return GLib.SOURCE_REMOVE

        async def _quarantine_file(self, path: Path) -> QuarantineEntry:
            return await asyncio.to_thread(self._vault.quarantine, path)

        def _refresh_quarantine(self) -> None:
            if self._quarantine_page is not None:
                self._quarantine_page.refresh()

        def _build_page(self, page_id: str, manager: DatabaseManager | None) -> Gtk.Widget:
            if page_id == "scan":
                page = ScanPage(
                    self._scan_controller,
                    record_scan=self._store_scan_result,
                    quarantine=self._quarantine_file,
                    on_quarantined=self._refresh_quarantine,
                    default_profile_id=self._settings.default_profile_id,
                )
                self._scan_page = page
                self._pages[page_id] = page.root
                return page.root
            if page_id == "databases":
                page = AntivirusDatabasesPage(manager or _default_database_manager())
                self._pages[page_id] = page
                return page
            if page_id == "diagnostics":
                page = DiagnosticsPage(self._checks)
                self._pages[page_id] = page.root
                return page.root
            if page_id == "history":
                page = HistoryPage(self._history_store)
                self._history_page = page
                self._pages[page_id] = page.root
                return page.root
            if page_id == "quarantine":
                page = QuarantinePage(self._vault, key_manager=self._key_manager)
                self._quarantine_page = page
                self._pages[page_id] = page.root
                return page.root
            if page_id == "settings":
                page = SettingsPage(
                    self._settings_store,
                    on_changed=self._on_settings_changed,
                    on_about=self.show_about,
                )
                self._pages[page_id] = page.root
                return page.root
            raise ValueError(f"unknown page id: {page_id}")

    class ClamGuardianApp(Adw.Application):
        """The ClamGuardian application: one window, startup diagnostics."""

        def __init__(self, **kwargs: object) -> None:
            super().__init__(
                application_id="io.github.clamguardian.ClamGuardian", **kwargs
            )
            self._window: MainWindow | None = None
            self._css_loaded = False
            self._add_action("about", self._on_about_action)
            self._add_action("quit", self._on_quit_action)
            self.set_accels_for_action("app.about", ["F1"])
            self.set_accels_for_action("app.quit", ["<primary>q"])
            self.connect("activate", self._on_activate)

        def _add_action(self, name: str, callback) -> None:
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", callback)
            self.add_action(action)

        def _on_activate(self, _app: Adw.Application) -> None:
            if self._window is None:
                if not self._css_loaded:
                    load_css()
                    self._css_loaded = True
                settings_store = SettingsStore()
                apply_color_scheme(settings_store.load().color_scheme)
                manager = _default_database_manager()
                self._window = MainWindow(
                    self,
                    manager=manager,
                    controller=ShieldTaskController(),
                    history_store=SqliteHistoryStore(default_history_db_path()),
                    settings_store=settings_store,
                )
                self._window.present()
                missing = critical_missing(self._window._checks)
                if missing:
                    self._window.show_diagnostics(missing)
            else:
                self._window.present()

        def _on_about_action(self, _action: object, _parameter: object) -> None:
            if self._window is not None:
                self._window.show_about()

        def _on_quit_action(self, _action: object, _parameter: object) -> None:
            self.quit()

    def run_ui(argv: Sequence[str] | None = None) -> int:
        """Run the GTK application main loop; returns the exit status."""
        app = ClamGuardianApp()
        arguments = [sys.argv[0]] if argv is None else list(argv)
        return int(app.run(arguments))

else:

    def run_ui(argv: Sequence[str] | None = None) -> None:
        """Import-safety shim used on headless systems without PyGObject."""
        del argv
        raise RuntimeError(
            "ClamGuardian UI requires PyGObject with GTK 4 and Libadwaita; "
            "install the 'gtk' extra or use `clamguardian doctor` instead"
        )

    ClamGuardianApp = None
    MainWindow = None


__all__ = [
    "GTK_AVAILABLE",
    "ClamGuardianApp",
    "MainWindow",
    "run_ui",
]
