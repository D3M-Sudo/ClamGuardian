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
from clamguardian.history.interface import HistoryError, HistoryStore


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


@pytest.mark.asyncio
async def test_history_detail_loads_full_record_instead_of_list_summary() -> None:
    from clamguardian.ui.history_page import load_history_detail

    summary = _record(status=ScanStatus.INFECTED, threats=())
    full_record = _record(
        status=ScanStatus.INFECTED,
        threats=("Eicar-Test-Signature",),
    )

    class ProductionContractStore:
        async def get_scan(self, scan_id: str):
            assert scan_id == summary["id"]
            return full_record

    detail = await load_history_detail(ProductionContractStore(), summary)

    assert detail is full_record
    assert detail["threats"] == ["Eicar-Test-Signature"]



@pytest.mark.parametrize(
    ("action", "expected_fragment"),
    [
        ("initial load", "could not be loaded"),
        ("refresh", "Previously loaded records are still shown"),
        ("status filter", "could not be filtered"),
        ("limit change", "could not be updated"),
        ("purge", "Existing records were kept"),
    ],
)
def test_history_error_message_is_action_specific(
    action: str, expected_fragment: str
) -> None:
    from clamguardian.ui.history_page import _history_error_message

    assert expected_fragment in _history_error_message(action)


@pytest.mark.parametrize(
    "action",
    ["initial load", "refresh", "status filter", "limit change"],
)
def test_failed_history_load_preserves_last_good_records_and_reports_error(
    action: str, caplog: pytest.LogCaptureFixture
) -> None:
    from clamguardian.ui.history_page import (
        _history_error_message,
        _report_history_error,
        _resolve_history_load,
    )

    existing = [_record(target="/tmp/last-good.txt")]
    failure = OSError("database unavailable")
    notifications: list[str] = []

    def report_error(operation: str, error: Exception) -> None:
        _report_history_error(operation, error, notifications.append)

    records, succeeded = _resolve_history_load(
        existing, None, failure, action, report_error
    )

    assert succeeded is False
    assert records is existing
    assert records[0]["target"] == "/tmp/last-good.txt"
    assert notifications == [_history_error_message(action)]
    assert f"History {action} failed" in caplog.text
    assert "database unavailable" in caplog.text


def test_successful_history_load_replaces_last_good_records() -> None:
    from clamguardian.ui.history_page import _resolve_history_load

    existing = [_record(target="/tmp/old.txt")]
    replacement = [_record(target="/tmp/new.txt")]

    records, succeeded = _resolve_history_load(
        existing, replacement, None, "refresh",
        lambda *_args: pytest.fail("unexpected error"),
    )

    assert succeeded is True
    assert records == replacement
    assert records is not existing


def test_purge_failure_is_logged_and_notifies_without_exposing_error_details(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from clamguardian.ui.history_page import _report_history_error

    notifications: list[str] = []
    failure = OSError("/home/user/private/history.sqlite: permission denied")

    _report_history_error("purge", failure, notifications.append)

    assert len(notifications) == 1
    assert "could not be deleted" in notifications[0]
    assert "/home/user/private" not in notifications[0]
    assert "/home/user/private" in caplog.text


@pytest.mark.parametrize("error_type", [HistoryError, OSError])
def test_history_detail_failure_reports_safe_feedback_and_logs_exception(
    error_type: type[Exception],
    caplog: pytest.LogCaptureFixture,
) -> None:
    from clamguardian.ui.history_page import (
        _history_error_message,
        _report_history_error,
        _resolve_history_detail,
    )

    notifications: list[str] = []
    failure = error_type("/home/user/private/history.sqlite: database unavailable")
    errors: list[tuple[str, Exception]] = []

    def report_error(action: str, error: Exception) -> None:
        errors.append((action, error))
        _report_history_error(action, error, notifications.append)

    _resolve_history_detail(
        None,
        failure,
        report_error,
        notifications.append,
        lambda: pytest.fail("missing-record refresh must not run on lookup error"),
        lambda _record: pytest.fail("detail dialog must not open on lookup error"),
    )

    assert errors == [("detail", failure)]
    assert notifications == [_history_error_message("detail")]
    assert "/home/user/private" not in notifications[0]
    assert "/home/user/private/history.sqlite" in caplog.text
    assert "History detail failed" in caplog.text


def test_history_detail_missing_record_notifies_and_refreshes_without_error_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from clamguardian.ui.history_page import _resolve_history_detail

    notifications: list[str] = []
    errors: list[tuple[str, Exception]] = []
    refreshed: list[bool] = []

    _resolve_history_detail(
        None,
        None,
        lambda action, error: errors.append((action, error)),
        notifications.append,
        lambda: refreshed.append(True),
        lambda _record: pytest.fail("detail dialog must not open for a missing record"),
    )

    assert notifications == ["This scan record is no longer available."]
    assert errors == []
    assert refreshed == [True]
    assert "no longer exists" in caplog.text
    assert "ERROR" not in caplog.text


def test_history_detail_success_opens_detail_without_notifications() -> None:
    from clamguardian.ui.history_page import _resolve_history_detail

    record = _record()
    displayed: list[object] = []

    _resolve_history_detail(
        record,
        None,
        lambda *_args: pytest.fail("unexpected error callback"),
        lambda _message: pytest.fail("unexpected missing-record notification"),
        lambda: pytest.fail("unexpected History refresh"),
        displayed.append,
    )

    assert displayed == [record]



@pytest.mark.parametrize(
    ("outcome", "expected_message"),
    [
        ("error", "Scan details could not be loaded. Please try again."),
        ("missing", "This scan record is no longer available."),
    ],
)
def test_history_detail_callback_delivers_toast_and_refreshes_missing_record(
    outcome: str,
    expected_message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise row activation through the async callback into GTK toast delivery."""
    if not gtk_works():
        pytest.skip("GTK not usable in this environment")

    from clamguardian.ui import database_pages

    pending_callbacks = []

    def capture_async(coro, on_done=None) -> None:
        coro.close()
        if on_done is not None:
            pending_callbacks.append(on_done)

    monkeypatch.setattr(database_pages, "run_async", capture_async)

    class RecordingToastOverlay:
        def __init__(self) -> None:
            self.toasts = []

        def add_toast(self, toast) -> None:
            self.toasts.append(toast)

    store = _StubStore()
    page = history_page_module.HistoryPage(store)
    window = history_page_module.Gtk.Window()
    overlay = RecordingToastOverlay()
    window.toast_overlay = overlay
    window.set_child(page.root)

    summary = _record()
    page._on_record_activated(None, summary)

    # The first callback belongs to HistoryPage's constructor load; the
    # second is the detail lookup initiated by row activation.
    assert len(pending_callbacks) == 2
    if outcome == "error":
        pending_callbacks[1](None, OSError("private database path"))
    else:
        pending_callbacks[1](None, None)

    assert len(overlay.toasts) == 1
    assert overlay.toasts[0].get_title() == expected_message

    if outcome == "missing":
        # Missing rows trigger a real refresh request after the toast.
        assert len(pending_callbacks) == 3
    else:
        assert len(pending_callbacks) == 2

    window.destroy()
