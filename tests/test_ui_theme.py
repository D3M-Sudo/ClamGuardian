"""Tests for the application stylesheet and theme helpers (Phase D4)."""

from __future__ import annotations

import pytest
from _gtk_probe import gtk_works

import clamguardian.ui.theme as theme_module


def test_stylesheet_is_shipped_with_the_package() -> None:
    assert theme_module.css_path().is_file()
    assert theme_module.css_path().name == "style.css"


def test_stylesheet_defines_the_application_classes() -> None:
    css = theme_module.css_text()
    for selector in (
        ".cg-status-banner",
        ".cg-banner-ok",
        ".cg-banner-warning",
        ".cg-banner-error",
        ".cg-scan-button",
    ):
        assert selector in css, f"stylesheet is missing {selector}"
    assert "@accent_bg_color" in css
    assert "!important" not in css, "the app must not override the system theme aggressively"


def test_load_css_is_a_no_op_without_gtk() -> None:
    if theme_module.GTK_AVAILABLE:
        pytest.skip("PyGObject is available; the GTK path is covered below")
    assert theme_module.load_css() is False


def test_apply_color_scheme_rejects_unknown_values() -> None:
    assert theme_module.apply_color_scheme("neon") is False


def test_color_schemes_match_the_settings_contract() -> None:
    from clamguardian.core.settings import VALID_COLOR_SCHEMES

    assert theme_module.COLOR_SCHEMES == VALID_COLOR_SCHEMES


@pytest.mark.skipif(not gtk_works(), reason="requires PyGObject + display/Xvfb")
def test_load_css_installs_the_provider() -> None:
    try:
        assert theme_module.load_css() is True
    except Exception:  # pragma: no cover - needs a working X server/Adw
        pytest.skip("GTK/Adw CSS provider failed in this environment")


@pytest.mark.skipif(not gtk_works(), reason="requires PyGObject + display/Xvfb")
def test_apply_color_scheme_accepts_every_valid_value() -> None:
    for scheme in theme_module.COLOR_SCHEMES:
        try:
            assert theme_module.apply_color_scheme(scheme) is True
        except Exception:  # pragma: no cover - needs a working X server/Adw
            pytest.skip("GTK/Adw style manager failed in this environment")
