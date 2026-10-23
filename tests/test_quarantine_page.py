"""Tests for the desktop Quarantine page (Phase D3).

Pure logic and headless import-safety run everywhere; real widget
construction runs only with PyGObject and a display (see the GTK smoke job
in the release gate for Xvfb coverage).
"""

from __future__ import annotations

import pytest

import clamguardian.ui.quarantine_page as quarantine_page_module


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


def test_format_size_units() -> None:
    assert quarantine_page_module.format_size(512) == "512 B"
    assert quarantine_page_module.format_size(2048) == "2.0 KiB"
    assert quarantine_page_module.format_size(3 * 1024 * 1024) == "3.0 MiB"
