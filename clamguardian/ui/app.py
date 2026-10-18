"""GTK4/Libadwaita application shell for ClamGuardian.

`ClamGuardianApp` owns a single `MainWindow` built around
`Adw.NavigationSplitView`, in the layout of the approved desktop plan
(Malwarebytes-style sidebar mapped to Libadwaita): Scan, History,
Quarantine, Databases and Diagnostics.

Phase D1 ships the shell, the Databases page (existing database pages
embedded in the window) and the real Diagnostics page; the Scan, History and
Quarantine pages arrive with Phases D2 and D3 and are rendered as honest
placeholders until then. At startup the app runs the Core dependency
checks and, when a critical dependency is missing, switches to the
Diagnostics page and presents a blocking dialog with the remedy.

The module is import-safe on headless systems without PyGObject, following
the shim pattern of :mod:`clamguardian.ui.database_pages`.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

from ..core.base import ScanResult
from ..core.diagnostics import CheckResult, critical_missing, run_dependency_checks
from ..core.quarantine import QuarantineVault
from ..history.backend import SqliteHistoryStore, default_history_db_path
from .controller import ShieldTaskController
from .database_pages import GTK_AVAILABLE
from .diagnostics_page import DiagnosticsPage
from .history_page import HistoryPage
from .quarantine_key import QuarantineKeyManager
from .quarantine_page import QuarantinePage
from .scan_page import ScanPage

if GTK_AVAILABLE:  # pragma: no cover - exercised only on systems with PyGObject
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, GLib, Gtk

    from ..databases import DatabaseManager
    from .database_pages import AntivirusDatabasesPage
    from .diagnostics_page import DiagnosticsPage

    #: Sidebar entries as ``(stack id, label, icon)``; page construction for
    #: each entry lives in :meth:`MainWindow._build_page`.
    SIDEBAR_ENTRIES: tuple[tuple[str, str, str], ...] = (
        ("scan", "Scan", "system-run-symbolic"),
        ("history", "History", "document-open-recent-symbolic"),
        ("quarantine", "Quarantine", "channel-secure-symbolic"),
        ("databases", "Databases", "database-symbolic"),
        ("diagnostics", "Diagnostics", "emblem-system-symbolic"),
    )

    #: Placeholder descriptions for the pages that arrive in later phases.
    PLACEHOLDER_DESCRIPTIONS: dict[str, str] = {
        "scan": "The scan page lands with desktop phase D2: target chooser, "
        "profile dropdown, in-flight state and result cards.",
        "databases": "Third-party signature databases managed through the app-data "
        "directory.",
        "diagnostics": "Dependency status and per-distro remediation guides.",
    }

    def _alert_dialog(heading: str, body: str) -> Adw.Window:
        """Build a modal alert, compatible with Libadwaita < 1.5.

        `Adw.AlertDialog` (1.5+) is preferred; on older runtimes (e.g. the
        GNOME 46+ images still shipping Libadwaita 1.4) the equivalent
        `Adw.MessageDialog` is returned instead, so the startup diagnostics
        dialog works everywhere ClamGuardian supports.
        """
        if hasattr(Adw, "AlertDialog"):
            # AlertDialog is modal by default (Libadwaita 1.5+); there is no
            # `modal` property to set.
            dialog = Adw.AlertDialog(heading=heading, body=body)
            dialog.add_response("ok", "OK")
            return dialog
        dialog = Adw.MessageDialog(heading=heading, body=body)
        dialog.add_response("ok", "OK")
        dialog.set_default_response("ok")
        dialog.set_close_response("ok")
        return dialog

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
        """Main window: sidebar navigation + page stack + toast overlay."""

        def __init__(
            self,
            application: Adw.Application,
            *,
            checks: Sequence[CheckResult] | None = None,
            manager: DatabaseManager | None = None,
            controller: ShieldTaskController | None = None,
            history_store: SqliteHistoryStore | None = None,
            key_manager: QuarantineKeyManager | None = None,
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
                key_manager if key_manager is not None else QuarantineKeyManager(default_history_db_path())
            )
            self._vault = QuarantineVault(
                self._key_manager.directory,
                self._key_manager.load_or_create(),
            )

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

            split = Adw.NavigationSplitView()
            split.set_sidebar(Adw.NavigationPage(title="ClamGuardian", child=sidebar))
            split.set_content(
                Adw.NavigationPage(title="ClamGuardian", child=self._toast_overlay)
            )
            self.set_content(split)

        # -- public API ----------------------------------------------------

        @property
        def toast_overlay(self) -> Adw.ToastOverlay:
            return self._toast_overlay

        def show_page(self, page_id: str) -> None:
            """Switch the content stack and the sidebar selection to *page_id*."""
            if page_id not in self._pages:
                return
            self._stack.set_visible_child_name(page_id)
            self._sidebar.select_row(self._sidebar_rows[page_id])

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
            dialog = _alert_dialog("ClamAV is not ready to scan", body)
            dialog.present(self)

        # -- internals -----------------------------------------------------

        def _on_sidebar_selected(
            self, _sidebar: Gtk.ListBox, row: Gtk.ListBoxRow | None
        ) -> None:
            if row is None:
                return
            page_id = getattr(row, "page_id", None)
            if page_id:
                self._stack.set_visible_child_name(page_id)

        def _build_page(self, page_id: str, manager: DatabaseManager | None) -> Gtk.Widget:
            icons = {entry_id: icon for entry_id, _label, icon in SIDEBAR_ENTRIES}
            labels = {entry_id: label for entry_id, label, _icon in SIDEBAR_ENTRIES}
            if page_id == "scan":
                page = ScanPage(self._scan_controller, record_scan=self._store_scan_result)
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
                self._pages[page_id] = page.root
                return page.root
            if page_id == "quarantine":
                page = QuarantinePage(self._vault, key_manager=self._key_manager)
                self._pages[page_id] = page.root
                return page.root
            placeholder = Adw.StatusPage(
                icon_name=icons[page_id],
                title=labels[page_id],
                description=PLACEHOLDER_DESCRIPTIONS[page_id],
            )
            self._pages[page_id] = placeholder
            return placeholder

    class ClamGuardianApp(Adw.Application):
        """The ClamGuardian application: one window, startup diagnostics."""

        def __init__(self, **kwargs: object) -> None:
            super().__init__(
                application_id="io.github.clamguardian.ClamGuardian", **kwargs
            )
            self._window: MainWindow | None = None
            self.connect("activate", self._on_activate)

        def _on_activate(self, _app: Adw.Application) -> None:
            if self._window is None:
                manager = _default_database_manager()
                self._window = MainWindow(
                    self,
                    manager=manager,
                    controller=ShieldTaskController(),
                    history_store=SqliteHistoryStore(default_history_db_path()),
                )
                self._window.present()
                missing = critical_missing(self._window._checks)
                if missing:
                    self._window.show_diagnostics(missing)

        async def _store_scan_result(self, result: ScanResult) -> None:
            """Persist *result* to the history store off the GTK loop."""
            await self._history_store.record_scan(result)

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