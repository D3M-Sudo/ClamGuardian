"""Tests for the desktop History page (Phase D3).

Pure logic and headless import-safety run everywhere; real widget
construction runs only with PyGObject and a display (see the GTK smoke job
in the release gate for Xvfb coverage).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from _gtk_probe import gtk_works

import clamguardian.ui.history_page as history_page_module
from clamguardian.core.base import ScanStatus
from clamguardian.history.interface import HistoryStore


class _StubStore(HistoryStore):
    """Minimal in-memory store used to drive HistoryPage."""

    def __init__(self, records: list[dict] | None = None) -> None:
        self._records = records or []

    async def list_scans(self, status: str | None = None, limit: int = 25) -> list[dict]:
        records = list(self._records)
        if status is not None:
            records = [r for r in records if r.get("status") == status]
        return records[:limit]

    async def clear_history(self) -> None:
        self._records.clear()


def _record(
    target: str = "/tmp/test.txt",
    status: ScanStatus = ScanStatus.CLEAN,
    threats: tuple[str, ...] = (),
    started: float = 1_700_000_000.0,
) -> dict:
    return {
        "id": "rec-1",
        "target": target,
        "status": status.value,
        "threats": list(threats),
        "engine": "clamscan",
        "profile_id": "default",
        "files_scanned": 1,
        "started_at": datetime.fromtimestamp(started, tz=UTC),
        "finished_at": datetime.fromtimestamp(started + 10, tz=UTC),
    }


def test_module_exposes_boolean_gtk_flag() -> None:
    assert isinstance(history_page_module.GTK_AVAILABLE, bool)


def test_status_icon_covers_every_status() -> None:
    for status in ScanStatus:
        icon = history_page_module.status_icon(status)
        assert icon.endswith("-symbolic")


def test_filter_options_exhaustive() -> None:
    labels = [label for label, _status in history_page_module.FILTER_OPTIONS]
    assert "All statuses" in labels
    assert "Clean" in labels
    assert "Infected" in labels
    assert "Error" in labels
    assert "Timeout" in labels
    assert "Cancelled" in labels


@pytest.mark.asyncio
async def test_page_list_renders_records() -> None:
    if not gtk_works():
        pytest.skip("GTK not usable in this environment")

    store = _StubStore([_record()])
    page = history_page_module.HistoryPage(store)
    assert page.root is not None


@pytest.mark.skipif(
    history_page_module.GTK_AVAILABLE, reason="headless shim only without PyGObject"
)
def test_history_page_shim_raises_headless() -> None:
    with pytest.raises(RuntimeError, match="PyGObject"):
        history_page_module.HistoryPage(None)  # type: ignore[arg-type]
