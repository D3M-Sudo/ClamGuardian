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

__all__ = [
    "GTK_AVAILABLE",
    "AddDatabaseDialog",
    "AntivirusDatabasesPage",
    "ShieldTaskController",
    "ThirdPartyDatabaseRow",
    "ThirdPartyDatabasesPage",
    "build_database_navigation",
    "run_async",
]
