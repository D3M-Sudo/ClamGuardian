"""Desktop notifications for completed scans.

Notification payloads are intentionally **content-free**: they never contain
the scanned path, file names or engine diagnostics, because notifications are
rendered on lock screens and in notification history.  Only status and counts
are disclosed.

The module is import-safe on headless systems without PyGObject.
"""

from __future__ import annotations

from ..core.base import ScanResult, ScanStatus

try:  # pragma: no cover - exercised only on systems with PyGObject
    from gi.repository import Gio

    GTK_AVAILABLE = True
except Exception:  # pragma: no cover - headless environments
    GTK_AVAILABLE = False

__all__ = [
    "GTK_AVAILABLE",
    "NOTIFICATION_ID",
    "notification_payload",
    "notify_scan_result",
]

#: Stable notification id: a newer scan replaces the previous notification.
NOTIFICATION_ID = "scan-finished"

#: Application icon name used by the notification.
APP_ICON = "io.github.clamguardian.ClamGuardian"


def notification_payload(result: ScanResult) -> tuple[str, str] | None:
    """Return ``(title, body)`` for *result*, or ``None`` when not notified.

    Cancelled scans are user-initiated and deliberately silent.
    """
    if result.status is ScanStatus.CLEAN:
        return (
            "Scan complete",
            f"No threats found. {result.files_scanned} file(s) scanned.",
        )
    if result.status is ScanStatus.INFECTED:
        count = len(result.threats)
        return (
            "Threats found",
            f"{count} threat(s) detected. Open ClamGuardian to review them.",
        )
    if result.status in (ScanStatus.ERROR, ScanStatus.TIMEOUT):
        return (
            "Scan failed",
            "The scan did not complete. Open ClamGuardian to review the error.",
        )
    return None


def notify_scan_result(app: object, result: ScanResult) -> bool:
    """Send a desktop notification for *result*.

    Returns ``True`` when the notification was handed to the application.
    Failures (headless systems, no portal, an application that is not
    registered) are swallowed: a missed notification must never break the
    scan flow.
    """
    payload = notification_payload(result)
    if payload is None or not GTK_AVAILABLE or app is None:
        return False
    title, body = payload
    try:
        notification = Gio.Notification.new(title)
        notification.set_body(body)
        notification.set_icon(Gio.ThemedIcon.new(APP_ICON))
        notification.set_priority(Gio.NotificationPriority.NORMAL)
        app.send_notification(NOTIFICATION_ID, notification)
    except Exception:  # noqa: BLE001 - notifications are best effort
        return False
    return True


def withdraw_scan_notification(app: object) -> None:
    """Remove a previous scan notification, if any."""
    if not GTK_AVAILABLE or app is None:
        return
    try:
        app.withdraw_notification(NOTIFICATION_ID)
    except Exception:  # noqa: BLE001 - notifications are best effort
        return
