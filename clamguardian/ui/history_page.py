"""History page for the GTK4/Libadwaita desktop application.

The page lists recorded scans from a :class:`~clamguardian.history.interface.HistoryStore`,
with status filtering, per-record detail dialogs and purge. It never touches
SQLite directly — all persistence goes through the injected store abstraction,
so the UI stays testable and layer-isolated.

The module is import-safe on headless systems without PyGObject, following
the shim pattern of :mod:`clamguardian.ui.database_pages`.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import TYPE_CHECKING

from ..core.base import ScanStatus
from ..history.interface import HistoryStore
from .scan_page import _remove_all_children

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

#: Symbolic icon per scan status.
STATUS_ICONS: dict[ScanStatus, str] = {
    ScanStatus.CLEAN: "emblem-ok-symbolic",
    ScanStatus.INFECTED: "dialog-error-symbolic",
    ScanStatus.ERROR: "dialog-error-symbolic",
    ScanStatus.TIMEOUT: "dialog-warning-symbolic",
    ScanStatus.CANCELLED: "process-stop-symbolic",
}

#: Human labels for scan statuses.
STATUS_LABELS: dict[ScanStatus, str] = {
    ScanStatus.CLEAN: "Clean",
    ScanStatus.INFECTED: "Infected",
    ScanStatus.ERROR: "Error",
    ScanStatus.TIMEOUT: "Timeout",
    ScanStatus.CANCELLED: "Cancelled",
}

#: Filter options for the history list: ``(label, status_or_None)``.
FILTER_OPTIONS: tuple[tuple[str, str | None], ...] = (
    ("All statuses", None),
    ("Clean", ScanStatus.CLEAN.value),
    ("Infected", ScanStatus.INFECTED.value),
    ("Error", ScanStatus.ERROR.value),
    ("Timeout", ScanStatus.TIMEOUT.value),
    ("Cancelled", ScanStatus.CANCELLED.value),
)

#: Maximum records shown per page.
DEFAULT_LIMIT = 25


def status_icon(status: ScanStatus) -> str:
    """Return the symbolic icon name for *status*."""
    return STATUS_ICONS[status]


def format_timestamp(value: datetime) -> str:
    """Render a timestamp in the user's locale, short form."""
    return value.strftime("%Y-%m-%d %H:%M")


if TYPE_CHECKING:
    from .controller import ShieldTaskController


if GTK_AVAILABLE:  # pragma: no cover - exercised only on systems with PyGObject

    class HistoryPage:
        """List recorded scans with status filtering, detail dialogs and purge."""

        def __init__(self, history_store: HistoryStore) -> None:
            self._history_store = history_store
            self._status_filter: str | None = None
            self._limit = DEFAULT_LIMIT
            self._records: Sequence = []
            self._rows: dict[str, Adw.ActionRow] = {}
            self._detail_dialog: Adw.Dialog | Adw.MessageDialog | None = None

            self._root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
            self._root.set_vexpand(True)
            self._root.set_hexpand(True)

            # -- History card ----------------------------------------------
            self._list_box = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
            group = Adw.PreferencesGroup(title="History")
            purge_button = Gtk.Button(label="Purge")
            purge_button.add_css_class("flat")
            purge_button.connect("clicked", self._on_purge_clicked)
            group.set_header_suffix(purge_button)

            self._status_combo = self._build_status_combo()
            self._limit_combo = self._build_limit_combo()

            group.add(self._status_combo)
            group.add(self._limit_combo)
            group.add(self._list_box)
            self._root.append(group)
            # -- empty state -----------------------------------------------
            self._empty_page = Adw.StatusPage(
                icon_name="emblem-system-symbolic",
                title="No scans recorded",
                description="Run a scan from the Scan page to record history here.",
            )
            self._empty_page.set_visible(False)
            self._root.append(self._empty_page)

            # -- initial load ----------------------------------------------
            from .database_pages import run_async

            def _done(_result: object, error: Exception | None) -> None:
                if error is None:
                    self._render()

            run_async(self._load_records(), _done)

        # -- public API ----------------------------------------------------

        @property
        def root(self) -> Gtk.Widget:
            """The top-level widget to embed into the application shell."""
            return self._root

        # -- internals -----------------------------------------------------

        def _build_status_combo(self) -> Adw.ComboRow:
            model = Gtk.StringList.new([label for label, _status in FILTER_OPTIONS])
            row = Adw.ComboRow(title="Status", model=model)
            row.set_selected(0)
            row.connect("notify::selected", self._on_status_changed)
            return row

        def _build_limit_combo(self) -> Adw.ComboRow:
            model = Gtk.StringList.new(["25", "50", "100"])
            row = Adw.ComboRow(title="Show", model=model)
            row.set_selected(0)
            row.connect("notify::selected", self._on_limit_changed)
            return row

        async def _load_records(self) -> Sequence:
            return await self._history_store.list_scans(
                status=self._status_filter,
                limit=self._limit,
            )

        def _render(self) -> None:
            _remove_all_children(self._list_box)
            self._rows = {}

            if not self._records:
                self._list_box.set_visible(False)
                self._empty_page.set_visible(True)
                return

            self._list_box.set_visible(True)
            self._empty_page.set_visible(False)

            for record in self._records:
                row = self._build_record_row(record)
                self._list_box.append(row)
                self._rows[record.id] = row

        def _build_record_row(self, record) -> Adw.ActionRow:
            status = ScanStatus(record.status)
            icon = Gtk.Image(icon_name=status_icon(status))
            icon.set_valign(Gtk.Align.CENTER)

            threats = record.threats if record.threats is not None else ()
            subtitle = f"{record.target}  ·  {format_timestamp(record.started_at)}"
            if threats:
                subtitle += f"  ·  {len(threats)} threat(s)"

            row = Adw.ActionRow(
                title=GLib.markup_escape_text(record.target),
                subtitle=GLib.markup_escape_text(subtitle),
            )
            row.add_suffix(icon)
            row.set_activatable(True)
            row.connect("activated", self._on_record_activated, record)
            return row

        def _on_status_changed(
            self, combo: Adw.ComboRow, _pspec: object
        ) -> None:
            index = combo.get_selected()
            if 0 <= index < len(FILTER_OPTIONS):
                self._status_filter = FILTER_OPTIONS[index][1]
            else:
                self._status_filter = None
            from .database_pages import run_async

            def _done(_result: object, error: Exception | None) -> None:
                if error is None:
                    self._render()

            run_async(self._load_records(), _done)

        def _on_limit_changed(
            self, combo: Adw.ComboRow, _pspec: object
        ) -> None:
            index = combo.get_selected()
            limits = [25, 50, 100]
            if 0 <= index < len(limits):
                self._limit = limits[index]
            from .database_pages import run_async

            def _done(_result: object, error: Exception | None) -> None:
                if error is None:
                    self._render()

            run_async(self._load_records(), _done)

        def _on_record_activated(
            self, _row: Adw.ActionRow, record: object
        ) -> None:
            self._show_detail(record)

        def _show_detail(self, record) -> None:
            if self._detail_dialog is not None:
                self._detail_dialog.close()
                self._detail_dialog = None

            threats = record.threats if record.threats is not None else ()
            profile_id = record.profile_id or "default"
            body_lines = [
                f"Target: {GLib.markup_escape_text(record.target)}",
                f"Status: {STATUS_LABELS.get(ScanStatus(record.status), record.status)}",
                f"Engine: {GLib.markup_escape_text(record.engine)}",
                f"Profile: {GLib.markup_escape_text(profile_id)}",
                f"Files scanned: {record.files_scanned}",
                f"Started: {format_timestamp(record.started_at)}",
                f"Finished: {format_timestamp(record.finished_at)}",
            ]
            if record.sha256:
                body_lines.append(f"SHA-256: {record.sha256}")
            if threats:
                body_lines.append("")
                body_lines.append("Threats:")
                for threat in threats:
                    body_lines.append(f"  • {GLib.markup_escape_text(threat)}")
            else:
                body_lines.append("")
                body_lines.append("No threats detected.")

            body = "\n".join(body_lines)

            if hasattr(Adw, "AlertDialog"):
                dialog = Adw.AlertDialog(
                    heading=f"Scan #{record.id[:8]}",
                    body=body,
                )
                dialog.add_response("ok", "OK")
            else:
                dialog = Adw.MessageDialog(
                    heading=f"Scan #{record.id[:8]}",
                    body=body,
                )
                dialog.add_response("ok", "OK")
                dialog.set_default_response("ok")
                dialog.set_close_response("ok")

            self._detail_dialog = dialog
            top = self._top_level()
            if top is not None:
                dialog.present(top)

        def _top_level(self) -> Gtk.Window | None:
            widget: Gtk.Widget = self._root
            while getattr(widget, "get_parent", lambda: None)() is not None:
                widget = widget.get_parent()
            return widget  # type: ignore[return-value]

        def _on_purge_clicked(self, _button: Gtk.Button) -> None:
            if hasattr(Adw, "AlertDialog"):
                dialog = Adw.AlertDialog(
                    heading="Purge history",
                    body=(
                        "This will delete all recorded scans and cannot be undone. "
                        "Continue?"
                    ),
                )
                dialog.add_response("cancel", "Cancel")
                dialog.add_response("purge", "Purge")
                dialog.set_default_response("cancel")
                dialog.set_close_response("cancel")
                dialog.connect("response", self._on_purge_confirmed)
            else:
                dialog = Adw.MessageDialog(
                    heading="Purge history",
                    body=(
                        "This will delete all recorded scans and cannot be undone. "
                        "Continue?"
                    ),
                )
                dialog.add_response("cancel", "Cancel")
                dialog.add_response("purge", "Purge")
                dialog.set_default_response("cancel")
                dialog.set_close_response("cancel")
                dialog.connect("response", self._on_purge_confirmed)

            self._detail_dialog = dialog
            top = self._top_level()
            if top is not None:
                dialog.present(top)

        def _on_purge_confirmed(
            self, _dialog: object, response: str
        ) -> None:
            if response != "purge":
                self._detail_dialog = None
                return
            from .database_pages import run_async

            def _done(_result: object, error: Exception | None) -> None:
                self._detail_dialog = None
                if error is None:
                    self._render()

            run_async(self._history_store.clear_history(), _done)


else:

    class HistoryPage:
        """Import-safety shim used on headless systems without PyGObject."""

        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs
            raise RuntimeError(
                "HistoryPage requires PyGObject with GTK 4 and Libadwaita; "
                "install the 'gtk' extra or use `clamguardian doctor` instead"
            )


__all__ = [
    "DEFAULT_LIMIT",
    "FILTER_OPTIONS",
    "GTK_AVAILABLE",
    "HAS_DISPLAY",
    "HistoryPage",
    "STATUS_ICONS",
    "STATUS_LABELS",
    "format_timestamp",
    "status_icon",
]
