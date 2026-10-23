"""Application stylesheet loading for the GTK4/Libadwaita shell.

The stylesheet is a package resource (``clamguardian/ui/style.css``) so it is
shipped by the wheel and by the Flatpak build without a separate packaging
manifest entry.  Loading is defensive: a missing or invalid stylesheet never
prevents the application from starting, it only means the stock Adwaita theme
is used.

The module is import-safe on headless systems without PyGObject.
"""

from __future__ import annotations

from pathlib import Path

try:  # pragma: no cover - exercised only on systems with PyGObject
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gdk, Gtk

    GTK_AVAILABLE = True
except Exception:  # pragma: no cover - headless environments
    GTK_AVAILABLE = False

__all__ = [
    "CSS_FILE_NAME",
    "GTK_AVAILABLE",
    "apply_color_scheme",
    "css_path",
    "css_text",
    "load_css",
]

#: Stylesheet file shipped next to this module.
CSS_FILE_NAME = "style.css"

#: Adw colour scheme names, mapped to ``Adw.ColorScheme`` at load time.
COLOR_SCHEMES: tuple[str, ...] = ("system", "light", "dark")


def css_path() -> Path:
    """Return the stylesheet path inside the installed package."""
    return Path(__file__).with_name(CSS_FILE_NAME)


def css_text() -> str:
    """Return the stylesheet contents (used by tests and as a fallback)."""
    return css_path().read_text(encoding="utf-8")


def load_css(display: object | None = None) -> bool:
    """Install the application stylesheet on *display*.

    Returns ``True`` when the provider was installed.  On headless systems,
    when no display is available, or when the stylesheet cannot be loaded,
    returns ``False`` and leaves the default theme untouched.
    """
    if not GTK_AVAILABLE:
        return False
    target = display if display is not None else Gdk.Display.get_default()
    if target is None:
        return False
    provider = Gtk.CssProvider()
    try:
        path = css_path()
        if path.is_file():
            provider.load_from_path(str(path))
        else:  # pragma: no cover - only possible in exotic installations
            provider.load_from_data(css_text().encode("utf-8"))
        Gtk.StyleContext.add_provider_for_display(
            target,
            provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
        )
    except Exception:  # noqa: BLE001 - styling must never break startup
        return False
    return True


def apply_color_scheme(scheme: str) -> bool:
    """Apply a ``system``/``light``/``dark`` preference to Libadwaita.

    Returns ``True`` when applied; ``False`` on headless systems or for an
    unknown value (the caller keeps the current scheme).
    """
    if not GTK_AVAILABLE or scheme not in COLOR_SCHEMES:
        return False
    mapping = {
        "system": Adw.ColorScheme.DEFAULT,
        "light": Adw.ColorScheme.FORCE_LIGHT,
        "dark": Adw.ColorScheme.FORCE_DARK,
    }
    Adw.StyleManager.get_default().set_color_scheme(mapping[scheme])
    return True
