"""GTK4/Libadwaita pages for third-party ClamAV database management.

The UI layer is a thin view over
:class:`~clamguardian.databases.manager.DatabaseManager`: it never downloads
files, verifies digests, installs artifacts or writes the state file. All
those responsibilities stay inside the database backend.

The module is import-safe on headless systems without PyGObject: GTK is
imported through a guarded block and, when unavailable, the exported page
classes become import-safety shims that fail only when instantiated.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Awaitable, Callable
from pathlib import Path

from ..databases.manager import DatabaseManager
from ..databases.models import DatabaseArtifact, DatabaseSource, DatabaseStatus, InstalledDatabase

try:  # pragma: no cover - exercised only on systems with PyGObject
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, GLib, Gtk

    GTK_AVAILABLE = True
except (ImportError, ValueError):  # pragma: no cover - headless environments
    GTK_AVAILABLE = False


STATUS_LABELS: dict[DatabaseStatus, str] = {
    DatabaseStatus.AVAILABLE: "Available",
    DatabaseStatus.INSTALLED: "Installed",
    DatabaseStatus.DISABLED: "Disabled",
    DatabaseStatus.UPDATING: "Updating…",
    DatabaseStatus.ERROR: "Update error",
}

AsyncDoneCallback = Callable[[object, Exception | None], None]
StatusCallback = Callable[[InstalledDatabase], Awaitable[None] | None]


def _invoke_idle(callback: AsyncDoneCallback, result: object, error: Exception | None) -> bool:
    callback(result, error)
    return False


def run_async(coro, on_done: AsyncDoneCallback | None = None) -> None:
    """Schedule ``coro`` without blocking the GTK main loop.

    If an asyncio loop is already running (GTK apps integrated with asyncio),
    the coroutine becomes a task on that loop and ``on_done`` fires on the
    loop thread. Otherwise the coroutine runs on a worker thread with its own
    loop and the callback is marshalled back with ``GLib.idle_add``.
    """
    try:
        loop: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None:
        task = loop.create_task(coro)

        async def _chain() -> None:
            try:
                result, error = await task, None
            except asyncio.CancelledError:  # pragma: no cover - app shutdown
                return
            except Exception as exc:  # noqa: BLE001 - surfaced to the caller
                result, error = None, exc
            if on_done is not None:
                on_done(result, error)

        loop.create_task(_chain())
        return

    def _worker() -> None:
        result, error = None, None
        try:
            result = asyncio.run(coro)
        except Exception as exc:  # noqa: BLE001 - surfaced to the caller
            error = exc
        if on_done is not None:
            if GTK_AVAILABLE:
                GLib.idle_add(_invoke_idle, on_done, result, error)
            else:
                on_done(result, error)

    threading.Thread(target=_worker, daemon=True).start()


class _GtkNotAvailable:
    """Import-safety shim applied to UI classes on headless systems."""

if not GTK_AVAILABLE:  # pragma: no cover - headless environments
    AntivirusDatabasesPage = _GtkNotAvailable
    AddDatabaseDialog = _GtkNotAvailable
    ThirdPartyDatabaseRow = _GtkNotAvailable
    ThirdPartyDatabasesPage = _GtkNotAvailable

    def build_database_navigation(manager: DatabaseManager) -> object:
        raise RuntimeError("PyGObject/GTK4/Libadwaita is not available on this system")

else:

    class AddDatabaseDialog(Adw.Dialog):
        """Libadwaita dialog that registers a new source through the manager."""

        FIELDS = (
            ("source_id", "Source ID", "e.g. malwarebytes"),
            ("name", "Name", "e.g. Malware DB"),
            ("description", "Description", "e.g. Community ClamAV signatures"),
            ("url", "Database URL", "https://…"),
            ("filename", "Filename", "e.g. malware.db"),
            ("sha256", "SHA-256 (optional)", "64 hexadecimal characters"),
        )

        def __init__(self, manager: DatabaseManager,
                     on_added: Callable[[DatabaseSource], None]) -> None:
            super().__init__(title="Add third-party database",
                             content_width=420, content_height=560)
            self._manager = manager
            self._on_added = on_added
            self._entries: dict[str, Gtk.Entry] = {}

            content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12,
                              margin_top=12, margin_bottom=12, margin_start=12, margin_end=12)

            for key, label, placeholder in self.FIELDS:
                caption = Gtk.Label(label=label, xalign=0)
                caption.add_css_class("heading")
                entry = Gtk.Entry(placeholder_text=placeholder)
                self._entries[key] = entry
                content.append(caption)
                content.append(entry)

            self._error_label = Gtk.Label(xalign=0, wrap=True, visible=False)
            self._error_label.add_css_class("error")
            content.append(self._error_label)

            scrolled = Gtk.ScrolledWindow(child=content, vexpand=True)

            cancel = Gtk.Button(label="Cancel")
            cancel.connect("clicked", lambda _b: self.close())
            add_button = Gtk.Button(label="Add database")
            add_button.add_css_class("suggested-action")
            add_button.connect("clicked", self._on_add_clicked)

            footer = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6,
                             margin_top=6, margin_bottom=6, margin_end=12)
            footer.append(Gtk.Box(hexpand=True))
            footer.append(cancel)
            footer.append(add_button)

            view = Adw.ToolbarView(top_bar=Adw.HeaderBar(), content=scrolled, bottom_bar=footer)
            self.set_child(view)


        def _show_error(self, message: str) -> None:
            self._error_label.set_text(message)
            self._error_label.set_visible(True)

        def _on_add_clicked(self, _button: Gtk.Button) -> None:
            self._error_label.set_visible(False)
            values = {key: entry.get_text().strip() for key, entry in self._entries.items()}

            if not values["source_id"]:
                self._show_error("Source ID is required.")
                return
            if not values["name"]:
                self._show_error("Name is required.")
                return
            if not values["url"].startswith("https://"):
                self._show_error("Database URL must use HTTPS.")
                return
            if not values["filename"] or Path(values["filename"]).name != values["filename"]:
                self._show_error("Filename must be a plain file name without path components.")
                return
            if values["source_id"] in {source.id for source in self._manager.sources}:
                self._show_error(f"Database source already exists: {values['source_id']}")
                return

            artifact = DatabaseArtifact(filename=values["filename"], url=values["url"],
                                        sha256=values["sha256"] or None)
            try:
                source = DatabaseSource(id=values["source_id"], name=values["name"],
                                        description=values["description"], artifacts=(artifact,))
                self._manager.add_source(source)
            except ValueError as exc:
                self._show_error(f"Database operation failed: {exc}")
                return
            self._on_added(source)
            self.close()

    class ThirdPartyDatabaseRow(Adw.ActionRow):
        """One configured third-party database source."""

        def __init__(self, manager: DatabaseManager, source: DatabaseSource,
                     page: ThirdPartyDatabasesPage) -> None:
            super().__init__(title=source.name, subtitle=source.description)
            self._manager = manager
            self._source = source
            self._page = page

            self._status_label = Gtk.Label(margin_end=6)
            self._status_label.add_css_class("dim-label")
            self._refresh_status()

            self._enabled_switch = Gtk.Switch(valign=Gtk.Align.CENTER)
            self._enabled_switch.set_active(source.enabled)
            self._enabled_switch.connect("state-set", self._on_enabled_toggled)

            self._auto_switch = Gtk.Switch(valign=Gtk.Align.CENTER)
            self._auto_switch.set_active(source.auto_update)
            self._auto_switch.connect("state-set", self._on_auto_update_toggled)

            enabled_caption = Gtk.Label(label="Enabled", xalign=0)
            enabled_caption.add_css_class("dim-label")
            auto_caption = Gtk.Label(label="Auto update", xalign=0)
            auto_caption.add_css_class("dim-label")

            enabled_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            enabled_box.append(self._enabled_switch)
            enabled_box.append(enabled_caption)
            auto_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            auto_box.append(self._auto_switch)
            auto_box.append(auto_caption)

            controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12,
                               valign=Gtk.Align.CENTER)
            controls.append(self._status_label)
            controls.append(enabled_box)
            controls.append(auto_box)

            update_button = Gtk.Button(icon_name="view-refresh-symbolic",
                                       valign=Gtk.Align.CENTER, tooltip_text="Update")
            update_button.connect("clicked", self._on_update_clicked)
            remove_button = Gtk.Button(icon_name="user-trash-symbolic",
                                       valign=Gtk.Align.CENTER, tooltip_text="Remove")
            remove_button.add_css_class("destructive-action")
            remove_button.connect("clicked", self._on_remove_clicked)

            self.add_suffix(controls)
            self.add_suffix(update_button)
            self.add_suffix(remove_button)

        def source_id(self) -> str:
            return self._source.id

        def set_status(self, status: DatabaseStatus, last_error: str | None = None) -> None:
            self._refresh_status(status)
            if status is DatabaseStatus.ERROR and last_error:
                self._page.show_error("Update error", last_error)

        def _refresh_status(self, status: DatabaseStatus | None = None) -> None:
            if status is None:
                try:
                    status = self._manager.status(self._source.id).status
                except KeyError:
                    status = DatabaseStatus.AVAILABLE
            self._status_label.set_text(STATUS_LABELS.get(status, str(status).capitalize()))

        def _on_enabled_toggled(self, _switch: Gtk.Switch, state: bool) -> bool:
            self._manager.set_enabled(self._source.id, state)
            self._page.schedule_refresh()
            return False

        def _on_auto_update_toggled(self, _switch: Gtk.Switch, state: bool) -> bool:
            self._manager.set_auto_update(self._source.id, state)
            self._page.schedule_refresh()
            return False

        def _on_update_clicked(self, _button: Gtk.Button) -> None:
            _button.set_sensitive(False)
            self._status_label.set_text(STATUS_LABELS[DatabaseStatus.UPDATING])

            def _done(result: object, error: Exception | None) -> None:
                _button.set_sensitive(True)
                self._page.on_update_finished(self._source.id, error)

            run_async(self._manager.update(self._source.id), _done)

        def _on_remove_clicked(self, _button: Gtk.Button) -> None:
            self._page.confirm_remove(self._source)

    class ThirdPartyDatabasesPage(Adw.NavigationPage):
        """Manage external ClamAV signature sources through DatabaseManager."""

        def __init__(self, manager: DatabaseManager) -> None:
            super().__init__(title="Third-party databases")
            self._manager = manager
            self._rows: dict[str, ThirdPartyDatabaseRow] = {}
            self._refresh_pending = False

            add_button = Gtk.Button(icon_name="list-add-symbolic", tooltip_text="Add database")
            add_button.connect("clicked", self._on_add_clicked)
            refresh_button = Gtk.Button(icon_name="view-refresh-symbolic",
                                        tooltip_text="Update all")
            refresh_button.connect("clicked", self._on_update_all_clicked)

            header = Adw.HeaderBar(title_widget=Adw.WindowTitle(title="Third-party databases"))
            header.pack_end(add_button)
            header.pack_end(refresh_button)

            self._toast_overlay = Adw.ToastOverlay()
            self._list_container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

            self._empty_status = Adw.StatusPage(
                title="No third-party databases",
                description="Add a source to manage external ClamAV signatures.")
            empty_button = Gtk.Button(label="Add database")
            empty_button.add_css_class("suggested-action")
            empty_button.add_css_class("pill")
            empty_button.connect("clicked", self._on_add_clicked)
            self._empty_status.set_child(empty_button)

            self._toast_overlay.set_child(self._list_container)
            self.set_child(Adw.ToolbarView(top_bar=header, content=self._toast_overlay))

            self._install_status_callback()
            self.rebuild_list()

        # -- manager wiring -------------------------------------------------

        def _install_status_callback(self) -> None:
            previous: StatusCallback | None = self._manager.status_callback

            def _on_status(installed: InstalledDatabase) -> Awaitable[None] | None:
                result = previous(installed) if previous is not None else None
                GLib.idle_add(self._on_status_changed, installed)
                return result

            self._manager.status_callback = _on_status

        def _on_status_changed(self, installed: InstalledDatabase) -> bool:
            row = self._rows.get(installed.source.id)
            if row is not None:
                row.set_status(installed.status, installed.last_error)
            return False

        # -- list rendering -------------------------------------------------

        def rebuild_list(self) -> None:
            for child in list(self._list_container.observe_children()):
                self._list_container.remove(child)
            self._rows.clear()

            sources = self._manager.sources
            if not sources:
                self._list_container.append(self._empty_status)
                return

            group = Adw.PreferencesGroup(title="External ClamAV signature databases")
            for source in sources:
                row = ThirdPartyDatabaseRow(self._manager, source, self)
                self._rows[source.id] = row
                group.add(row)
            self._list_container.append(group)

        def schedule_refresh(self) -> None:
            if self._refresh_pending:
                return
            self._refresh_pending = True
            GLib.idle_add(self._rebuild_idle)

        def _rebuild_idle(self) -> bool:
            self.rebuild_list()
            self._refresh_pending = False
            return False

        def _on_add_clicked(self, _button: Gtk.Button) -> None:
            dialog = AddDatabaseDialog(self._manager, self._on_database_added)
            dialog.present(self.root)

        def _on_database_added(self, source: DatabaseSource) -> None:
            self.rebuild_list()
            self._toast_overlay.add_toast(Adw.Toast(title=f"Added {source.name}"))

        def _on_update_all_clicked(self, _button: Gtk.Button) -> None:
            def _done(result: object, error: Exception | None) -> None:
                if error:
                    self._toast_overlay.add_toast(
                        Adw.Toast(title="Update failed", timeout=3))
                else:
                    self._toast_overlay.add_toast(
                        Adw.Toast(title="All databases updated", timeout=3))

            run_async(self._manager.update_all(), _done)

        def on_update_finished(self, source_id: str, error: Exception | None) -> None:
            row = self._rows.get(source_id)
            if row is not None:
                row._refresh_status()
            if error:
                self.show_error("Update error", str(error))

        def show_error(self, title: str, message: str) -> None:
            dialog = Adw.AlertDialog(
                heading=title,
                body=message,
                close_response="cancel",
                modal=True)
            dialog.add_response("cancel", "OK")
            dialog.present(self.root)

        def confirm_remove(self, source: DatabaseSource) -> None:
            dialog = Adw.AlertDialog(
                heading=f"Remove {source.name}?",
                body="This will delete the database source and its local files.",
                close_response="cancel",
                modal=True)
            dialog.add_response("cancel", "Cancel")
            dialog.add_response("remove", "Remove")
            dialog.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)
            dialog.connect("response", self._on_remove_response, source.id)
            dialog.present(self.root)

        def _on_remove_response(self, dialog: Adw.AlertDialog,
                               response: str, source_id: str) -> None:
            dialog.close()
            if response == "remove":
                try:
                    self._manager.remove_source(source_id)
                    self.rebuild_list()
                    self._toast_overlay.add_toast(Adw.Toast(title="Database removed"))
                except Exception as exc:  # noqa: BLE001 - user feedback
                    self.show_error("Removal failed", str(exc))


class AntivirusDatabasesPage(Adw.PreferencesPage):
    """Root preferences page with navigation to third-party database management."""

    def __init__(self, manager: DatabaseManager) -> None:
        super().__init__(title="Antivirus Databases")
        self._manager = manager

        group = Adw.PreferencesGroup(title="Third-party databases")
        group.add(build_database_navigation_row(manager))
        self.add(group)


def build_database_navigation(manager: DatabaseManager) -> Adw.NavigationView:
    """Build the navigation stack for third-party database management."""
    nav = Adw.NavigationView()
    page = ThirdPartyDatabasesPage(manager)
    nav.add(page)
    return nav


def build_database_navigation_row(manager: DatabaseManager) -> Adw.ActionRow:
    """Build an action row that navigates to the third-party database page."""
    row = Adw.ActionRow(title="Manage third-party databases",
                        subtitle="Add, update and remove external ClamAV signature sources")
    row.add_suffix(Gtk.Image(icon_name="go-next-symbolic"))
    row.set_activatable(True)

    def _on_activated(_row: Adw.ActionRow) -> None:
        nav = build_database_navigation(manager)
        dialog = Adw.Dialog(content=nav, content_width=800, content_height=600)
        dialog.present(row.root)

    row.connect("activated", _on_activated)
    return row


__all__ = [
    "GTK_AVAILABLE",
    "STATUS_LABELS",
    "AntivirusDatabasesPage",
    "AddDatabaseDialog",
    "ThirdPartyDatabaseRow",
    "ThirdPartyDatabasesPage",
    "build_database_navigation",
    "run_async",
]
