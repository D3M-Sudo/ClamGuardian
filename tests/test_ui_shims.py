"""Import-safety and pure-logic tests for the desktop UI modules (D1).

These tests run both on headless machines (no PyGObject) and on desktops:
the pure helpers are always exercised, while widget construction is only
asserted through the headless shim contract — real widget construction is
covered by the GTK smoke job in the release gate (Xvfb).
"""

from __future__ import annotations

import os

import pytest

import clamguardian.ui.app as app_module
import clamguardian.ui.diagnostics_page as diagnostics_module
from clamguardian.core.diagnostics import CheckResult, CheckStatus

#: Widget construction needs an actual display (CI's pytest job installs
#: PyGObject but runs headless; the Xvfb coverage lives in the release gate).
HAS_DISPLAY = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _result(status: CheckStatus, *, critical: bool = False) -> CheckResult:
    return CheckResult(
        id="sample",
        label="Sample",
        status=status,
        detail="detail",
        critical=critical,
        remedies={"debian": "sudo apt install sample"},
    )


def test_modules_expose_boolean_gtk_flag() -> None:
    assert isinstance(app_module.GTK_AVAILABLE, bool)
    assert isinstance(diagnostics_module.GTK_AVAILABLE, bool)


def test_status_icon_covers_every_status() -> None:
    for status in CheckStatus:
        icon = diagnostics_module.status_icon(status)
        assert icon.endswith("-symbolic")


def test_banner_content_healthy() -> None:
    icon, title, description = diagnostics_module.banner_content(
        [_result(CheckStatus.OK, critical=True)]
    )
    assert title == "Ready to scan"
    assert icon == diagnostics_module.STATUS_ICONS[CheckStatus.OK]
    assert "found on this system" in description


def test_banner_content_warnings_are_not_failures() -> None:
    icon, title, description = diagnostics_module.banner_content(
        [_result(CheckStatus.WARNING, critical=False)]
    )
    assert title == "Ready with warnings"
    assert icon == diagnostics_module.STATUS_ICONS[CheckStatus.WARNING]
    assert "clamscan fallback" in description


def test_banner_content_critical_failure_is_actionable() -> None:
    _icon, title, description = diagnostics_module.banner_content(
        [_result(CheckStatus.MISSING, critical=True)]
    )
    assert title == "Action needed"
    assert "Sample" in description
    assert "Scanning will not work" in description


def test_banner_status_is_the_worst_state() -> None:
    assert (
        diagnostics_module.banner_status(
            [_result(CheckStatus.OK, critical=True)]
        )
        is CheckStatus.OK
    )
    assert (
        diagnostics_module.banner_status(
            [_result(CheckStatus.WARNING), _result(CheckStatus.OK)]
        )
        is CheckStatus.WARNING
    )
    assert (
        diagnostics_module.banner_status(
            [
                _result(CheckStatus.WARNING),
                _result(CheckStatus.MISSING, critical=True),
            ]
        )
        is CheckStatus.MISSING
    )


@pytest.mark.skipif(
    diagnostics_module.GTK_AVAILABLE, reason="headless shim only without PyGObject"
)
def test_diagnostics_page_shim_raises_headless() -> None:
    with pytest.raises(RuntimeError, match="PyGObject"):
        diagnostics_module.DiagnosticsPage()


@pytest.mark.skipif(app_module.GTK_AVAILABLE, reason="headless shim only without PyGObject")
def test_app_shims_raise_headless() -> None:
    assert app_module.ClamGuardianApp is None
    assert app_module.MainWindow is None
    with pytest.raises(RuntimeError, match="PyGObject"):
        app_module.run_ui()


@pytest.mark.skipif(
    not diagnostics_module.GTK_AVAILABLE or not HAS_DISPLAY,
    reason="requires PyGObject + display/Xvfb",
)
def test_diagnostics_page_constructs_with_precomputed_checks() -> None:
    checks = [
        _result(CheckStatus.OK, critical=True),
        _result(CheckStatus.WARNING, critical=False),
    ]
    page = diagnostics_module.DiagnosticsPage(checks)
    assert tuple(page.checks) == tuple(checks)
    assert page.root is not None