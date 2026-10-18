"""Tests for the desktop Quarantine page (Phase D3).

Pure logic and headless import-safety run everywhere; real widget
construction runs only with PyGObject and a display (see the GTK smoke job
in the release gate for Xvfb coverage).
"""

from __future__ import annotations

import os

import pytest

import clamguardian.ui.quarantine_page as quarantine_page_module

#: Widget construction needs an actual display *and* a working GTK backend.
HAS_DISPLAY = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _gtk_works() -> bool:
    """Return whether GTK widgets can actually be constructed in this env."""
    if not quarantine_page_module.GTK_AVAILABLE:
        return False
    try:  # pragma: no cover - needs a real display/X server
        from gi.repository import Adw, Gtk

        Gtk.Box()
        Adw.StatusPage()
        return True
    except Exception:  # noqa: BLE001 - any failure means "no usable GTK here"
        return False


def test_module_exposes_boolean_gtk_flag() -> None:
    assert isinstance(quarantine_page_module.GTK_AVAILABLE, bool)


def test_state_icons_cover_quarantine_states() -> None:
    for key in ("ok", "missing", "corrupt"):
        icon = quarantine_page_module.STATE_ICONS.get(key)
        assert icon is not None
        assert icon.endswith("-symbolic")


@pytest.mark.skipif(
    quarantine_page_module.GTK_AVAILABLE, reason="headless shim only without PyGObject"
)
def test_quarantine_page_shim_raises_headless() -> None:
    with pytest.raises(RuntimeError, match="PyGObject"):
        quarantine_page_module.QuarantinePage(None)  # type: ignore[arg-type]
