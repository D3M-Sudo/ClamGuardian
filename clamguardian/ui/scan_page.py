"""Scan page for the GTK4/Libadwaita desktop application.

The page is a thin view over :class:`~clamguardian.ui.controller.ShieldTaskController`:
it renders a target chooser, a profile dropdown, a Scan/Cancel button pair, an
in-flight progress banner (indeterminate progress + elapsed timer + threat
counter) and a result card. When a scan finishes the result is optionally
persisted through a caller-supplied ``record_scan`` callback.

The module is import-safe on headless systems without PyGObject, following
the shim pattern of :mod:`clamguardian.ui.database_pages`.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING

from ..core.base import ScanResult, ScanStatus
from ..core.profiles import DEFAULT_REGISTRY, ScanProfile, resolve_profile

try:  # pragma: no cover - exercised only on systems with PyGObject
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, GLib, Gtk

    GTK_AVAILABLE = True
except Exception:  # pragma: no cover - headless environments
    GTK_AVAILABLE = False

if TYPE_CHECKING:
    from .controller import ShieldTaskController

#: Sidebar scope options: ``(label, recursive, icon)``.
SCOPE_OPTIONS: tuple[tuple[str, bool, str], ...] = (
    ("Folder", True, "folder-symbolic"),
    ("File", False, "text-x-generic-symbolic"),
    ("Home", True, "go-home-symbolic"),
)

#: Elapsed-time refresh interval (seconds).
_TICK_INTERVAL_SECONDS = 1


def _active_profile_id(combo: Adw.ComboRow) -> str | None:
    """Return the profile id currently selected in *combo*, or ``None``."""
    model = combo.get_model()
    if model is None:
        return None
    index = combo.get_selected()
    if index < 0:
        return None
    item = model.get_string(index)
    if item is None:
        return None
    profile = resolve_profile(item)
    return profile.id if profile is not None else None


def _scope_recursive(combo: Adw.ComboRow) -> bool:
    """Return whether the selected scope is recursive (folder / home)."""
    model = combo.get_model()
    if model is None:
        return True
    index = combo.get_selected()
    if index < 0:
        return True
    return SCOPE_OPTIONS[index][1]


if GTK_AVAILABLE:  # pragma: no cover - exercised only on systems with PyGObject

    def _remove_all_children(container: Gtk.Widget) -> None:
        """Remove every child from a Gtk/Adw container (defensive loop)."""
        while True:
            child = container.get_first_child()
            if child is None:
                return
            container.remove(child)

    def _alert_dialog(heading: str, body: str) -> Adw.Dialog:
        """Build a modal alert, compatible with Libadwaita < 1.5.

        Mirrors the helper in :mod:`clamguardian.ui.app` so this module never
        reaches into private names of another module.
        """
        if hasattr(Adw, "AlertDialog"):
            dialog = Adw.AlertDialog(heading=heading, body=body)
            dialog.add_response("ok", "OK")
            return dialog
        dialog = Adw.MessageDialog(heading=heading, body=body)
        dialog.add_response("ok", "OK")
        dialog.set_default_response("ok")
        dialog.set_close_response("ok")
        return dialog

    class ScanPage:
        """Target chooser, profile dropdown, Scan/Cancel and result card."""

        def __init__(
            self,
            controller: ShieldTaskController,
            *,
            record_scan: Callable[[ScanResult], Awaitable[None]] | None = None,
        ) -> None:
            self._controller = controller
            self._record_scan = record_scan
            self._in_flight = False
            self._elapsed = 0.0
            self._timer_id: int | None = None
            self._result: ScanResult | None = None

            self._root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
            self._root.set_vexpand(True)
            self._root.set_hexpand(True)

            # -- Scan card -------------------------------------------------
            self._cancel_button = self._build_cancel_button()
            scan_group = Adw.PreferencesGroup(title="Scan")
            scan_group.set_header_suffix(self._cancel_button)
            self._scan_button = self._build_scan_button(scan_group)
            self._target_row = self._build_target_row()
            self._scope_row = self._build_scope_row()
            self._profile_row = self._build_profile_row()

            scan_group.add(self._target_row)
            scan_group.add(self._scope_row)
            scan_group.add(self._profile_row)
            scan_group.add(self._scan_button)
            self._root.append(scan_group)
            # -- in-flight banner ------------------------------------------
            self._inflight_group = Adw.PreferencesGroup(title="Scan in progress")
            self._progress = Adw.ProgressBar()
            self._progress.set_show_text(True)
            self._progress.set_text("Scanning…")
            self._progress.pulse()
            self._elapsed_row = Adw.LabelRow(title="Elapsed")
            self._elapsed_row.set_title_subtitle("0s")
            self._threats_row = Adw.LabelRow(title="Threats")
            self._threats_row.set_title_subtitle("0")
            self._inflight_group.add(self._progress)
            self._inflight_group.add(self._elapsed_row)
            self._inflight_group.add(self._threats_row)
            self._inflight_group.set_visible(False)
            self._root.append(self._inflight_group)

            # -- result card -----------------------------------------------
            self._result_group = Adw.PreferencesGroup(title="Result")
            self._result_status = Adw.StatusPage()
            self._result_group.add(self._result_status)
            self._threats_list = Adw.PreferencesGroup(title="Threats")
            self._result_group.add(self._threats_list)
            self._result_group.set_visible(False)
            self._root.append(self._result_group)

            # -- signal bindings -------------------------------------------
            controller.connect("scan-started", self._on_scan_started)
            controller.connect("threat-detected", self._on_threat_detected)
            controller.connect("scan-finished", self._on_scan_finished)
            controller.connect("scan-cancelled", self._on_scan_cancelled)

        # -- public API ----------------------------------------------------

        @property
        def root(self) -> Gtk.Widget:
            """The top-level widget to embed into the application shell."""
            return self._root

        @property
        def in_flight(self) -> bool:
            """Whether a scan is currently running."""
            return self._in_flight

        @property
        def result(self) -> ScanResult | None:
            """The most recent scan result, or ``None`` before the first scan."""
            return self._result

        # -- internals -----------------------------------------------------

        def _build_scan_button(self, group: Adw.PreferencesGroup) -> Adw.ButtonRow:
            button = Adw.ButtonRow(title="Scan")
            button.set_icon_name("system-run-symbolic")
            button.add_css_class("suggested-action")
            button.connect("activated", self._on_scan_clicked)
            group.add(button)
            return button

        def _build_cancel_button(self) -> Adw.ButtonRow:
            button = Adw.ButtonRow(title="Cancel")
            button.set_icon_name("process-stop-symbolic")
            button.set_visible(False)
            button.connect("activated", self._on_cancel_clicked)
            return button

        def _build_target_row(self) -> Adw.EntryRow:
            row = Adw.EntryRow(title="Target")
            row.set_icon_name("folder-symbolic")
            row.set_placeholder_text("e.g. /home/user/Documents")
            row.set_text(str(Path.home()))
            return row

        def _build_scope_row(self) -> Adw.ComboRow:
            model = Gtk.StringList.new(
                [label for label, _recursive, _icon in SCOPE_OPTIONS]
            )
            row = Adw.ComboRow(title="Scope", model=model)
            row.set_selected(0)
            return row

        def _build_profile_row(self) -> Adw.ComboRow:
            profiles = DEFAULT_REGISTRY.list()
            model = Gtk.StringList.new([profile.name for profile in profiles])
            row = Adw.ComboRow(title="Profile", model=model)
            row.set_selected(0)
            row.set_activatable(False)
            return row

        def _on_scan_clicked(self, _button: Adw.ButtonRow) -> None:
            target_text = self._target_row.get_text().strip()
            if not target_text:
                self._show_error("Target is required", "Enter a file or folder to scan.")
                return
            target = Path(target_text).expanduser()
            if self._scope_row.get_selected() == 2:  # Home
                target = Path.home()
            recursive = _scope_recursive(self._scope_row)
            profile_id = _active_profile_id(self._profile_row)
            profile = resolve_profile(profile_id) if profile_id is not None else None

            self._start_scan(target, recursive=recursive, profile=profile)

        def _start_scan(
            self, target: Path, *, recursive: bool, profile: ScanProfile | None
        ) -> None:
            self._in_flight = True
            self._elapsed = 0.0
            self._result = None
            self._result_group.set_visible(False)
            _remove_all_children(self._threats_list)
            self._inflight_group.set_visible(True)
            self._progress.set_fraction(0.0)
            self._progress.pulse()
            self._elapsed_row.set_title_subtitle("0s")
            self._scan_button.set_visible(False)
            self._cancel_button.set_visible(True)
            self._timer_id = GLib.timeout_add_seconds(
                _TICK_INTERVAL_SECONDS, self._tick
            )
            from .database_pages import run_async

            async def _run() -> ScanResult:
                return await self._controller.scan(
                    target, recursive=recursive, profile=profile
                )

            def _done(_result: object, error: Exception | None) -> None:
                if error is not None and not isinstance(error, asyncio.CancelledError):
                    self._show_error("Scan failed", str(error))

            run_async(_run(), _done)

        def _tick(self) -> bool:
            if not self._in_flight:
                return False
            self._elapsed += 1.0
            self._elapsed_row.set_title_subtitle(f"{self._elapsed:.0f}s")
            self._progress.pulse()
            return True  # keep the timeout alive

        def _on_scan_started(self, _controller: object, _target_label: str) -> None:
            """Emitted by the controller once the concurrency slot is acquired."""
            self._threats_row.set_title_subtitle("0")

        def _on_threat_detected(
            self, _controller: object, _target: str, threat: str
        ) -> None:
            row = Adw.ActionRow(title=GLib.markup_escape_text(threat))
            row.set_icon_name("dialog-error-symbolic")
            row.set_activatable(False)
            self._threats_list.add(row)

        def _on_scan_finished(self, _controller: object, result: ScanResult) -> None:
            self._finish(result)

        def _on_scan_cancelled(self, _controller: object, _target_label: str) -> None:
            self._finish(
                ScanResult.cancelled(
                    str(Path.home())
                )  # target label only; path not carried by the signal
            )

        def _finish(self, result: ScanResult) -> None:
            self._in_flight = False
            if self._timer_id is not None:
                GLib.source_remove(self._timer_id)
                self._timer_id = None
            self._scan_button.set_visible(True)
            self._cancel_button.set_visible(False)
            self._inflight_group.set_visible(False)
            self._result = result
            self._result_group.set_visible(True)
            self._render_result(result)
            from .database_pages import run_async

            if self._record_scan is not None:
                run_async(self._record_scan(result), None)

        def _render_result(self, result: ScanResult) -> None:
            self._result_group.remove(self._result_status)
            if result.status is ScanStatus.CLEAN:
                self._result_status = Adw.StatusPage(
                    icon_name="emblem-ok-symbolic",
                    title="No threats found",
                    description=(
                        f"{result.files_scanned} file(s) scanned via {result.engine}."
                    ),
                )
            elif result.status is ScanStatus.INFECTED:
                self._result_status = Adw.StatusPage(
                    icon_name="dialog-error-symbolic",
                    title="Threats found",
                    description=(
                        f"{len(result.threats)} threat(s) detected in "
                        f"{result.files_scanned} file(s)."
                    ),
                )
            elif result.status is ScanStatus.CANCELLED:
                self._result_status = Adw.StatusPage(
                    icon_name="process-stop-symbolic",
                    title="Scan cancelled",
                    description="The scan was cancelled by the user.",
                )
            else:  # ERROR / TIMEOUT
                self._result_status = Adw.StatusPage(
                    icon_name="dialog-error-symbolic",
                    title="Scan failed",
                    description=result.error
                    or f"Scan ended with status {result.status.value}.",
                )
            self._result_group.add(self._result_status)

        def _show_error(self, heading: str, body: str) -> None:
            dialog = _alert_dialog(heading, body)
            window = self._top_level()
            if window is not None:
                dialog.present(window)

        def _top_level(self) -> Gtk.Window | None:
            widget: Gtk.Widget = self._root
            while getattr(widget, "get_parent", lambda: None)() is not None:
                widget = widget.get_parent()
            return widget

        def _on_cancel_clicked(self, _button: Adw.ButtonRow) -> None:
            self._controller.cancel_all()


else:

    class _ScanPageShim:
        """Import-safety shim used on headless systems without PyGObject."""

        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs
            raise RuntimeError(
                "ScanPage requires PyGObject with GTK 4 and Libadwaita; "
                "install the 'gtk' extra or use `clamguardian doctor` instead"
            )

    ScanPage = _ScanPageShim  # type: ignore[assignment, misc]


__all__ = ["GTK_AVAILABLE", "ScanPage", "SCOPE_OPTIONS"]
