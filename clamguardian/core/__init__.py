"""Core ClamGuardian primitives."""

from .base import BaseAVEngine, BaseThreatProvider, ScanProgress, ScanResult, ScanStatus
from .errors import ClamGuardianError, EngineError
from .quarantine import QuarantineEntry, QuarantineVault
from .runner import ScanTaskRunner

__all__ = [
    "BaseAVEngine",
    "BaseThreatProvider",
    "ScanProgress",
    "ScanResult",
    "ScanStatus",
    "ClamGuardianError",
    "EngineError",
    "QuarantineEntry",
    "QuarantineVault",
    "ScanTaskRunner",
]
