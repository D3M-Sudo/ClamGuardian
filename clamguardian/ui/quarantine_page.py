"""Quarantine page for the GTK4/Libadwaita desktop application.

The page lists encrypted vault entries from a
:class:`~clamguardian.core.quarantine.QuarantineVault`, providing restore to an
arbitrary destination and delete.  Every vault call is synchronous by design
(the ciphertext is streamed in chunks); the page wraps those calls in a
coroutine so they run off the GTK main loop through ``run_async``.

The module is import-safe on headless systems without PyGObject, following
the shim pattern of :mod:`clamguardian.ui.database_pages`.
"""

from __future__ import annotations

import contextlib
import os
from datetime import datetime
from pathlib import Path

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


def format_size(size: int) -> str:
    """Format a byte count for a row subtitle."""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KiB"
    return f"{size / 1024 / 1024:.1f} MiB"


def _as_entries(result: object) -> list[QuarantineEntry]:
    """Coerce an async callback payload into a list of vault entries."""
    if not isinstance(result, (list, tuple)):
        return []
    return [entry for entry in result if isinstance(entry, QuarantineEntry)]


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
            # Kept for API compatibility with the shell; the vault already
            # owns the key it was constructed with, so restore/delete do not
            # need the manager.
            self._key_manager = key_manager
            self._entries: list[QuarantineEntry] = []
            self._rows: dict[str, Adw.ActionRow] = {}
            self._detail_dialog: object | None = None

            self._root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
            self._root.set_vexpand(True)
            self._root.set_hexpand(True)

            self._group = Adw.PreferencesGroup(title="Quarantine")
            self._group.set_margin_start(12)
            self._group.set_margin_end(12)
            self._group.set_margin_top(8)
            self._group.set_margin_bottom(8)

            refresh_button = Gtk.Button(label="Refresh")
            refresh_button.add_css_class("flat")
            refresh_button.connect("clicked", self._on_refresh_clicked)
            self._group.set_header_suffix(refresh_button)

            self._summary_row = Adw.ActionRow(
                title="Encrypted vault",
                subtitle="Loading…",
                activatable=False,
            )
            self._summary_row.add_prefix(
                Gtk.Image(icon_name="channel-secure-symbolic")
            )
            self._group.add(self._summary_row)

            self._empty_page = Adw.StatusPage(
                icon_name="channel-secure-symbolic",
                title="Quarantine is empty",
                description=(
                    "Quarantine a detected file from the Scan page to see it here."
                ),
            )
            self._empty_page.set_visible(False)
            self._group.add(self._empty_page)

            self._root.append(self._group)
            self.refresh()

        # -- public API ----------------------------------------------------

        @property
        def root(self) -> Gtk.Widget:
            """The top-level widget to embed into the application shell."""
            return self._root

        @property
        def entries(self) -> tuple[QuarantineEntry, ...]:
            """The entries currently displayed."""
            return tuple(self._entries)

        def refresh(self) -> None:
            """Reload the vault list off the GTK loop."""
            from .database_pages import run_async

            async def _load() -> list[QuarantineEntry]:
                return list(self._vault.list_entries())

            def _done(result: object, error: Exception | None) -> None:
                if error is not None:
                    self._summary_row.set_subtitle(f"Could not read the vault: {error}")
                    return
                self._entries = _as_entries(result)
                self._render()

            run_async(_load(), _done)

        # -- rendering -----------------------------------------------------

        def _render(self) -> None:
            for row in self._rows.values():
                self._group.remove(row)
            self._rows = {}

            self._summary_row.set_subtitle(
                f"{len(self._entries)} encrypted record(s)"
                if self._entries
                else "No quarantined files"
            )
            self._empty_page.set_visible(not self._entries)

            for entry in self._entries:
                row = self._build_record_row(entry)
                self._group.add(row)
                self._rows[entry.item_id] = row

            # PreferencesGroup.add appends: keep the empty state last.
            self._group.remove(self._empty_page)
            self._group.add(self._empty_page)

        def _build_record_row(self, entry: QuarantineEntry) -> Adw.ActionRow:
            created = datetime.fromtimestamp(entry.created_at)
            subtitle = (
                f"{format_size(entry.size)}  ·  {format_timestamp(created)}  ·  "
                f"{entry.original_path}"
            )
            row = Adw.ActionRow(
                title=GLib.markup_escape_text(entry.original_name),
                subtitle=GLib.markup_escape_text(subtitle),
            )
            row.add_prefix(Gtk.Image(icon_name="channel-secure-symbolic"))
            row.add_suffix(Gtk.Image(icon_name="go-next-symbolic"))
            row.set_activatable(True)
            row.connect("activated", self._on_entry_activated, entry)
            return row

        def _on_entry_activated(self, _row: Adw.ActionRow, entry: QuarantineEntry) -> None:
            self._show_details(entry)

        # -- detail / restore / delete -------------------------------------

        def _show_details(self, entry: QuarantineEntry) -> None:
            from .dialogs import alert_dialog, top_level_window

            self._close_detail()
            created = datetime.fromtimestamp(entry.created_at)
            body = "\n".join(
                [
                    f"Original path: {GLib.markup_escape_text(entry.original_path)}",
                    f"Size: {format_size(entry.size)}",
                    f"Quarantined: {format_timestamp(created)}",
                    "",
                    "Restoring writes the file back to a folder you choose. "
                    "Deleting removes the encrypted record permanently.",
                ]
            )
            dialog = alert_dialog(
                "Quarantined file",
                body,
                responses=(
                    ("close", "Close"),
                    ("restore", "Restore"),
                    ("delete", "Delete"),
                ),
                default_response="close",
                close_response="close",
            )
            dialog.connect("response", self._on_detail_response, entry)
            self._detail_dialog = dialog
            window = top_level_window(self._root)
            if window is not None:
                dialog.present(window)

        def _on_detail_response(
            self, _dialog: object, response: str, entry: QuarantineEntry
        ) -> None:
            self._detail_dialog = None
            if response == "restore":
                self._choose_destination(entry)
            elif response == "delete":
                self._confirm_delete(entry)

        def _choose_destination(self, entry: QuarantineEntry) -> None:
            """Ask for a folder and restore *entry* there."""

            def _restore_to(destination: Path | None) -> None:
                if destination is None:
                    return
                from .database_pages import run_async

                async def _restore() -> Path:
                    return self._vault.restore(entry.item_id, destination)

                def _done(result: object, error: Exception | None) -> None:
                    if error is not None:
                        self._show_error("Restore failed", str(error))
                        return
                    self._show_info("Restored", str(result))
                    self.refresh()

                run_async(_restore(), _done)

            self._pick_destination(_restore_to)

        def _pick_destination(self, on_selected) -> None:
            """Ask for a folder asynchronously (no GTK3 ``run()``)."""
            window = self._top_level()

            if hasattr(Gtk, "FileDialog"):
                dialog = Gtk.FileDialog(title="Select restore destination")

                def _done(source: Gtk.FileDialog, result: object) -> None:
                    try:
                        folder = source.select_folder_finish(result)
                    except GLib.Error:
                        return
                    path = folder.get_path() if folder is not None else None
                    on_selected(Path(path) if path else None)

                dialog.select_folder(window, None, _done)
                return

            if hasattr(Gtk, "FileChooserNative"):  # pragma: no cover - older GTK4
                chooser = Gtk.FileChooserNative.new(
                    "Select restore destination",
                    window,
                    Gtk.FileChooserAction.SELECT_FOLDER,
                    "Select",
                    "Cancel",
                )

                def _response(dialog: object, response: int) -> None:
                    filename = (
                        dialog.get_filename()
                        if response == Gtk.ResponseType.ACCEPT
                        else None
                    )
                    dialog.destroy()
                    on_selected(Path(filename) if filename else None)

                chooser.connect("response", _response)
                chooser.show()
                return

            self._show_error(  # pragma: no cover - very old GTK4
                "No folder picker available",
                "This GTK version does not provide a folder chooser.",
            )

        def _confirm_delete(self, entry: QuarantineEntry) -> None:
            from .dialogs import alert_dialog, top_level_window

            dialog = alert_dialog(
                "Delete quarantine entry",
                (
                    f"{GLib.markup_escape_text(entry.original_name)}\n\n"
                    "This permanently removes the encrypted record and cannot "
                    "be undone. Continue?"
                ),
                responses=(("cancel", "Cancel"), ("delete", "Delete")),
                default_response="cancel",
                close_response="cancel",
            )
            dialog.connect("response", self._on_delete_confirmed, entry)
            window = top_level_window(self._root)
            if window is not None:
                dialog.present(window)

        def _on_delete_confirmed(
            self, _dialog: object, response: str, entry: QuarantineEntry
        ) -> None:
            if response != "delete":
                return
            from .database_pages import run_async

            async def _delete() -> None:
                self._vault.delete(entry.item_id)

            def _done(_result: object, error: Exception | None) -> None:
                if error is not None:
                    self._show_error("Delete failed", str(error))
                    return
                self.refresh()

            run_async(_delete(), _done)

        # -- helpers -------------------------------------------------------

        def _on_refresh_clicked(self, _button: Gtk.Button) -> None:
            self.refresh()

        def _close_detail(self) -> None:
            if self._detail_dialog is None:
                return
            with contextlib.suppress(Exception):
                self._detail_dialog.close()
            self._detail_dialog = None

        def _show_info(self, heading: str, body: str) -> None:
            from .dialogs import alert_dialog, top_level_window

            dialog = alert_dialog(heading, body)
            window = top_level_window(self._root)
            if window is not None:
                dialog.present(window)

        def _show_error(self, heading: str, body: str) -> None:
            self._show_info(heading, body)

        def _top_level(self) -> Gtk.Window | None:
            from .dialogs import top_level_window

            return top_level_window(self._root)

else:

    class QuarantinePage:
        """Import-safety shim used on headless systems without PyGObject."""

        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs
            raise RuntimeError(
                "QuarantinePage requires PyGObject with GTK 4 and Libadwaita; "
                "install the 'gtk' extra or use `clamguardian doctor` instead"
            )


__all__ = [
    "GTK_AVAILABLE",
    "QuarantinePage",
    "STATE_ICONS",
    "STATE_LABELS",
    "format_size",
    "format_timestamp",
]
