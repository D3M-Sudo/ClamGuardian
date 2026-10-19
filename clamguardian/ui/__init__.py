"""GTK/Libadwaita UI integration layer.

All GTK-dependent imports are guarded so the package stays importable on
headless systems (CI, tests) where PyGObject is not installed.
"""

from __future__ import annotations

from .database_pages import (
    GTK_AVAILABLE,
    AddDatabaseDialog,
    AntivirusDatabasesPage,
    ThirdPartyDatabaseRow,
    ThirdPartyDatabasesPage,
    build_database_navigation,
    run_async,
)

try:
    from .controller import ShieldTaskController
except ImportError:  # pragma: no cover - PyGObject absent on headless systems
    ShieldTaskController = None  # type: ignore[assignment,misc]

from .diagnostics_page import (
    DiagnosticsPage,
    banner_content,
    status_icon,
)
from .settings_page import SettingsPage

try:
    from .app import ClamGuardianApp, MainWindow, run_ui
except (ImportError, RuntimeError):  # pragma: no cover - headless systems
    ClamGuardianApp = None  # type: ignore[assignment,misc]
    MainWindow = None  # type: ignore[assignment,misc]

    def run_ui(argv=None):  # type: ignore[misc]
        """Import-safety shim: raise a clear error on headless systems."""
        del argv
        raise RuntimeError(
            "ClamGuardian UI requires PyGObject with GTK 4 and Libadwaita; "
            "install the 'gtk' extra or use `clamguardian doctor` instead"
        )


__all__ = [
    "GTK_AVAILABLE",
    "AddDatabaseDialog",
    "AntivirusDatabasesPage",
    "ClamGuardianApp",
    "DiagnosticsPage",
    "MainWindow",
    "ShieldTaskController",
    "SettingsPage",
    "ThirdPartyDatabaseRow",
    "ThirdPartyDatabasesPage",
    "banner_content",
    "build_database_navigation",
    "run_async",
    "run_ui",
    "status_icon",
]
