"""M4-B2 store contract: the public History API.

The store is deliberately an *abstraction*: consumer code (CLI, future GTK,
future scheduler) depends on :class:`HistoryStore`, never on SQLite directly.
The concrete backend lives in :mod:`clamguardian.history.backend`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from ..core.base import ScanResult
from .models import HistoryRecord


class HistoryError(Exception):
    """Raised when an explicitly requested history/storage operation fails.

    ``record_scan`` may raise this without altering the underlying
    :class:`~clamguardian.core.base.ScanResult` -- a persistence failure never
    retroactively changes a completed scan's outcome.
    """


@runtime_checkable
class HistoryStore(Protocol):
    """Asynchronous contract for reading and writing scan history.

    Error semantics (must hold for every backend):

    * ``get_scan(nonexistent)`` -> ``None``
    * ``delete_scan(nonexistent)`` -> ``False``
    * ``clear_history()`` -> number of deleted scan rows
    * invalid API arguments (e.g. an unknown ``status``, ``limit <= 0``) ->
      :class:`ValueError`
    * storage/backend failure -> :class:`HistoryError`

    History is append-oriented; there is deliberately no ``update``, ``watch``,
    ``subscribe`` or ``get_statistics``. ``list_scans`` does not load threat
    details; use :meth:`get_scan` for the full record.
    """

    async def record_scan(self, result: ScanResult) -> HistoryRecord: ...

    async def get_scan(self, scan_id: str) -> HistoryRecord | None: ...

    async def list_scans(
        self,
        *,
        status: str | None = None,
        profile_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
        ascending: bool = False,
    ) -> list[HistoryRecord]: ...

    async def delete_scan(self, scan_id: str) -> bool: ...

    async def clear_history(self) -> int: ...

    async def count_scans(self, *, status: str | None = None) -> int: ...

    async def close(self) -> None: ...