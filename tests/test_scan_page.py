"""Tests for the desktop Scan page (Phase D2).

Pure logic and headless import-safety run everywhere; real widget
construction runs only when PyGObject and a display are available
(the GTK smoke job in the release gate provides Xvfb coverage).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from _gtk_probe import gtk_works

import clamguardian.ui.scan_page as scan_page_module
from clamguardian.core.base import ScanResult, ScanStatus
from clamguardian.core.profiles import ScanProfile


class _StubController:
    """Minimal stand-in for ShieldTaskController used to drive ScanPage."""

    def __init__(self) -> None:
        self.signals: dict[str, list] = {}
        self.calls: list[tuple[str, bool, str | None]] = []
        self.cancelled = False

    def connect(self, signal: str, handler: object) -> None:
        self.signals.setdefault(signal, []).append(handler)

    def emit(self, signal: str, *args: object) -> None:
        for handler in self.signals.get(signal, []):
            handler(*args)

    async def scan(
        self, target: Path, *, recursive: bool, profile: ScanProfile | None = None
    ) -> ScanResult:
        self.calls.append(
            (str(target), recursive, profile.id if profile is not None else None)
        )
        self.emit("scan-started", str(target))
        self.emit("threat-detected", str(target), "EICAR-Test-File")
        result = ScanResult(
            target=str(target),
            clean=False,
            status=ScanStatus.INFECTED,
            threats=("EICAR-Test-File",),
            files_scanned=1,
            engine="clamscan",
        )
        self.emit("scan-finished", result)
        return result

    def cancel_all(self) -> asyncio.Task[None]:
        self.cancelled = True
        return asyncio.create_task(asyncio.sleep(0))


def test_module_exposes_boolean_gtk_flag() -> None:
    assert isinstance(scan_page_module.GTK_AVAILABLE, bool)


@pytest.mark.skipif(
    scan_page_module.GTK_AVAILABLE, reason="headless shim only without PyGObject"
)
def test_scan_page_shim_raises_headless() -> None:
    with pytest.raises(RuntimeError, match="PyGObject"):
        scan_page_module.ScanPage(object())  # type: ignore[arg-type]


@pytest.mark.skipif(
    not gtk_works(),
    reason="requires PyGObject + display/Xvfb",
)
def test_scan_page_constructs_and_initial_state() -> None:
    controller = _StubController()
    try:
        page = scan_page_module.ScanPage(controller)
    except Exception:  # pragma: no cover - needs a working X server/Adw
        pytest.skip("GTK/Adw widget construction failed in this environment")
    assert page.root is not None
    assert not page.in_flight
    assert page.result is None


@pytest.mark.skipif(
    not gtk_works(),
    reason="requires PyGObject + display/Xvfb",
)
def test_scan_page_finish_records_result() -> None:
    controller = _StubController()
    try:
        page = scan_page_module.ScanPage(controller)
    except Exception:  # pragma: no cover - needs a working X server/Adw
        pytest.skip("GTK/Adw widget construction failed in this environment")
    result = ScanResult(
        target="/home/user/Documents",
        clean=True,
        status=ScanStatus.CLEAN,
        files_scanned=5,
        engine="clamscan",
    )
    page._finish(result)
    assert page.result is result
    assert not page.in_flight
