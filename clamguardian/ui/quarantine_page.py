"""Quarantine page for the GTK4/Libadwaita desktop application.

The page lists encrypted vault entries from a
:class:`~clamguardian.core.quarantine.QuarantineVault`, providing restore to an
arbitrary destination and delete. Each record is rendered under the control of
the injected vault, so the UI stays testable and layer-isolated.

The module is import-safe on headless systems without PyGObject, following the
shim pattern of :mod:`clamguardian.ui.database_pages`.
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from ..core.quarantine import QuarantineEntry, QuarantineVault
from .quarantine_key import QuarantineKeyManager

try:  # pragma: no cover - exercised only on systems with PyGObject
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, GLib, Gtk

    GTK_AVAILABLE = True
except (ImportError, ValueError):  # pragma: no cover - headless environments
    GTK_AVAILABLE = False

#: Widget construction needs an actual display.
HAS_DISPLAY = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))

#: Symbolic icon per quarantine state.
STATE_ICONS: dict[str, str] = {
    "ok": "emblem-ok-symbolic",
    "missing": "dialog-error-symbolic",
    "corrupt": "process-stop-symbolic",
}

#: Human labels for quarantine states.
STATE_LABELS: dict[str, str] = {
    "ok": "OK",
    "missing": "File missing",
    "corrupt": "Corrupt record",
}


def format_timestamp(value: datetime) -> str:
    """Render a timestamp in the user's locale, short form."""
    return value.strftime("%Y-%m-%d %H:%M")


if TYPE_CHECKING:  # pragma: no cover
    pass


if GTK_AVAILABLE:  # pragma: no cover - exercised only on systems with PyGObject

    class QuarantinePage:
        """List encrypted vault entries with restore and delete."""

        def __init__(
            self,
            vault: QuarantineVault,
            *,
            key_manager: QuarantineKeyManager | None = None,
        ) -> None:
            self._vault = vault
            self._key_manager = key_manager
            self._entries: list[QuarantineEntry] = []
            self._rows: dict[str, Adw.ActionRow] = {}
            self._selection: str | None = None
            self._detail_dialog: Adw.Dialog | Adw.MessageDialog | None = None

            self._root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
            self._root.set_vexpand(True)
            self._root.set_hexpand(True)

            # -- Quarantine card -------------------------------------------
            group = Adw.PreferencesGroup(title="Quarantine")
            group.set_margin_start(12)
            group.set_margin_end(12)
            group.set_margin_top(8)
            group.set_margin_bottom(8)

            purge_button = Gtk.Button(label="Delete selected")
            purge_button.add_css_class("flat")
            purge_button.set_visible(False)
            purge_button.connect("clicked", self._on_delete_clicked)
            group.set_header_suffix(purge_button)

            self._state_row = Gtk.Label(label="")
            group.add(self._state_row)
            self._empty_page = Adw.StatusPage(
                icon_name="emblem-system-symbolic",
                title="Quarantine is empty",
                description="Drag and drop files on the Scan page to quarantine them.",
            )
            group.add(self._empty_page)

            self._root.append(group)
            self._empty_page.set_visible(False)

            # -- initial load ----------------------------------------------
            from .database_pages import run_async

            def _done(_result: object, error: Exception | None) -> None:
                if error is None:
                    self._render()
                elif isinstance(error, ValueError):
                    self._state_row.set_label(f"Error: {error}")
                    self._state_row.set_visible(True)

            run_async(self._load_entries(), _done)

        # -- public API --------------------------------------------------

        @property
        def root(self) -> Gtk.Widget:
            """The top-level widget to embed into the application shell."""
            return self._root

        # -- internals ---------------------------------------------------

        def _load_entries(self) -> list[QuarantineEntry]:
            return list(self._vault.list_entries())

        def _render(self) -> None:
            purge_button = self._root.get_parent()  # placeholder for header suffix
            self._empty_page.set_visible(not self._entries)
            purge_button.set_visible(bool(self._selection))
            self._state_row.set_visible(False)

            for row in list(self._rows.values()):
                self._root.remove(row)
            self._rows = {}
            self._selection = None

            for entry in self._entries:
                row = self._build_record_row(entry)
                self._root.append(row)
                self._rows[entry.item_id] = row

        def _build_record_row(self, entry: QuarantineEntry) -> Adw.ActionRow:
            icon = Gtk.Image(icon_name="quarantine-symbolic")
            icon.set_valign(Gtk.Align.CENTER)

            created = datetime.fromtimestamp(entry.created_at)
            subtitle = (
                f"{GLib.markup_escape_text(entry.original_name)}  ·  "
                f"{entry.size / 1024 / 1024:.1f} MiB  ·  "
                f"{format_timestamp(created)}"
            )

            row = Adw.ActionRow(
                title=GLib.markup_escape_text(entry.original_name),
                subtitle=GLib.markup_escape_text(subtitle),
            )
            row.add_suffix(icon)
            row.set_activatable(True)
            row.connect("activated", self._on_entry_activated, entry.item_id)
            return row

        def _on_entry_activated(self, _row: Adw.ActionRow, _record: object, item_id: str) -> None:
            self._selection = item_id
            self._restore(item_id)

        def _restore(self, item_id: str) -> None:
            if self._key_manager is None:
                self._show_error("Quarantine key missing", "No key manager is available.")
                return

            from .database_pages import run_async

            destination = self._pick_destination()
            if destination is None:
                return

            def _done(result: object, error: Exception | None) -> None:
                if error is None:
                    self._show_ok("Restored", str(result))
                else:
                    self._show_error("Restore failed", str(error))
                self._load_entries()

            run_async(self._vault.restore(item_id, Path(destination)), _done)

        def _show_ok(self, heading: str, body: str) -> None:
            dialog = Adw.AlertDialog(heading=heading, body=body)
            dialog.add_response("ok", "OK")
            window = self._top_level()
            if window is not None:
                dialog.present(window)

        @staticmethod
        def _pick_destination() -> str | None:
            """Ask the user for a restore destination (folder chooser)."""
            from gi.repository import Gtk

            dialog = Gtk.FileChooserNative.new(
                "Select restore destination",
                None,
                Gtk.FileChooserAction.SELECT_FOLDER,
                ("Cancel", Gtk.ResponseType.CANCEL),
                ("Select", Gtk.ResponseType.ACCEPT),
            )
            dialog.set_default_size(600, 400)
            response = dialog.run()
            destination = None
            if response == Gtk.ResponseType.ACCEPT:
                destination = dialog.get_filename()
            dialog.destroy()
            return destination

        def _show_error(self, heading: str, body: str) -> None:
            dialog = Adw.AlertDialog(heading=heading, body=body)
            dialog.add_response("ok", "OK")
            window = self._top_level()
            if window is not None:
                dialog.present(window)

        def _top_level(self) -> Gtk.Window | None:
            widget: Gtk.Widget = self._root
            while getattr(widget, "get_parent", lambda: None)() is not None:
                widget = widget.get_parent()
            return widget

        def _on_delete_clicked(self, _button: Gtk.Button) -> None:
            if self._selection is None:
                return
            item_id = self._selection
            dialog = Adw.AlertDialog(
                heading="Delete quarantine entry",
                body=(
                    "This will permanently remove the encrypted record and cannot "
                    "be undone. Continue?"
                ),
            )
            dialog.add_response("cancel", "Cancel")
            dialog.add_response("delete", "Delete")
            dialog.set_default_response("cancel")
            dialog.set_close_response("cancel")
            dialog.connect("response", self._on_delete_confirmed, item_id)
            self._detail_dialog = dialog
            top = self._top_level()
            if top is not None:
                dialog.present(top)

        def _on_delete_confirmed(self, _dialog: object, response: str, item_id: str) -> None:
            if response != "delete":
                self._detail_dialog = None
                return
            from .database_pages import run_async

            def _done(_result: object, error: Exception | None) -> None:
                self._detail_dialog = None
                if error is None:
                    self._load_entries()

            run_async(self._vault.delete(item_id), _done)  # type: ignore[func-returns-value]

else:

    class QuarantinePage:
        """Import-safety shim used on headless systems without PyGObject."""

        def __init__(self, *args: object, **kwargs: object) -> None:
                del args, kwargs
                raise RuntimeError(
                "QuarantinePage requires PyGObject with GTK 4 and Libadwaita; "
                    "install the 'gtk' extra or use `clamguardian doctor` instead"
                )


__all__ = ["GTK_AVAILABLE", "QuarantinePage", "STATE_ICONS", "STATE_LABELS", "format_timestamp"]
