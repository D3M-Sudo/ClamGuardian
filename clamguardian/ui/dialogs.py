"""Small dialog helpers shared by the desktop pages.

Libadwaita introduced ``Adw.AlertDialog`` in 1.5.  The application supports
runtimes where only ``Adw.MessageDialog`` exists, so every page must build
alerts through this module instead of referencing the newer class directly.

The module is import-safe on headless systems without PyGObject.

"""

from __future__ import annotations

from collections.abc import Sequence

try:  # pragma: no cover - exercised only on systems with PyGObject
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gtk

    GTK_AVAILABLE = True
except Exception:  # pragma: no cover - headless environments
    GTK_AVAILABLE = False

__all__ = [
    "GTK_AVAILABLE",
    "alert_dialog",
    "top_level_window",
]

#: Default single-button response used by informational alerts.
DEFAULT_RESPONSES: tuple[tuple[str, str], ...] = (("ok", "OK"),)


def alert_dialog(
    heading: str,
    body: str,
    *,
    responses: Sequence[tuple[str, str]] = DEFAULT_RESPONSES,
    default_response: str | None = None,
    close_response: str | None = None,
):
    """Build a modal alert compatible with Libadwaita < 1.5.

    ``responses`` is a sequence of ``(response_id, label)`` pairs.  The
    returned object exposes ``present(parent)`` and the ``response`` signal in
    both the ``Adw.AlertDialog`` and ``Adw.MessageDialog`` variants.
    """
    if not GTK_AVAILABLE:  # pragma: no cover - defensive
        raise RuntimeError("alert_dialog requires PyGObject with GTK 4 and Libadwaita")

    if hasattr(Adw, "AlertDialog"):
        dialog = Adw.AlertDialog(heading=heading, body=body)
    else:  # pragma: no cover - only on Libadwaita < 1.5
        dialog = Adw.MessageDialog(heading=heading, body=body)
    for response_id, label in responses:
        dialog.add_response(response_id, label)
    if default_response is not None:
        dialog.set_default_response(default_response)
    if close_response is not None:
        dialog.set_close_response(close_response)
    return dialog


def top_level_window(widget: Gtk.Widget) -> Gtk.Window | None:
    """Return the toplevel window containing *widget*, or ``None``."""
    current: Gtk.Widget = widget
    while True:
        parent = getattr(current, "get_parent", lambda: None)()
        if parent is None:
            return current if isinstance(current, Gtk.Window) else None
        current = parent
