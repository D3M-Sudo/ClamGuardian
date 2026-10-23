"""Tests for the scan-completion notifications (Phase D4)."""

from __future__ import annotations

from clamguardian.core.base import ScanResult, ScanStatus
from clamguardian.ui.notifications import (
    notification_payload,
    notify_scan_result,
    withdraw_scan_notification,
)


def _result(status: ScanStatus, *, threats: tuple[str, ...] = ()) -> ScanResult:
    return ScanResult(
        target="/home/user/private/secret.txt",
        clean=status is ScanStatus.CLEAN,
        status=status,
        threats=threats,
        files_scanned=7,
        engine="clamscan",
    )


def test_clean_payload_reports_counts() -> None:
    payload = notification_payload(_result(ScanStatus.CLEAN))
    assert payload == ("Scan complete", "No threats found. 7 file(s) scanned.")


def test_infected_payload_reports_only_the_count() -> None:
    payload = notification_payload(
        _result(ScanStatus.INFECTED, threats=("a", "b"))
    )
    assert payload is not None
    assert payload[0] == "Threats found"
    assert "2 threat(s)" in payload[1]


def test_error_and_timeout_payloads_are_generic() -> None:
    for status in (ScanStatus.ERROR, ScanStatus.TIMEOUT):
        payload = notification_payload(_result(status))
        assert payload is not None
        assert payload[0] == "Scan failed"


def test_cancelled_scan_is_silent() -> None:
    assert notification_payload(_result(ScanStatus.CANCELLED)) is None


def test_payload_never_leaks_paths_or_file_names() -> None:
    for status in ScanStatus:
        payload = notification_payload(_result(status, threats=("/tmp/x: EICAR FOUND",)))
        if payload is None:
            continue
        joined = f"{payload[0]} {payload[1]}"
        assert "secret.txt" not in joined
        assert "/home/user" not in joined
        assert "EICAR" not in joined


def test_notify_is_a_no_op_without_an_application() -> None:
    assert notify_scan_result(None, _result(ScanStatus.CLEAN)) is False


def test_withdraw_is_a_no_op_without_an_application() -> None:
    assert withdraw_scan_notification(None) is None
