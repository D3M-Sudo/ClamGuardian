"""Dedicated exception hierarchy for ClamGuardian core errors.

The chain is intentionally minimal: engines raise :class:`EngineError`
subclasses, the task runner and the GObject controller let them propagate
untouched so that any front-end (GTK, future CLI, headless) can decide how
to surface them. Core never prints and never swallows these exceptions.
"""

from __future__ import annotations


class ClamGuardianError(Exception):
    """Base class for all ClamGuardian core errors."""


class EngineError(ClamGuardianError):
    """Raised by AV engines when an operation cannot be completed.

    Cancellation and timeouts are *not* modelled with this exception: the
    former propagates as :class:`asyncio.CancelledError`, the latter is
    reported through :attr:`~clamguardian.core.base.ScanStatus.TIMEOUT`.
    """