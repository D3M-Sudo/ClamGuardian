"""Core ClamGuardian primitives."""

from .base import BaseAVEngine, BaseThreatProvider, ScanResult
from .quarantine import QuarantineEntry, QuarantineVault
from .runner import ScanTaskRunner

__all__ = ["BaseAVEngine", "BaseThreatProvider", "ScanResult", "QuarantineEntry", "QuarantineVault", "ScanTaskRunner"]
