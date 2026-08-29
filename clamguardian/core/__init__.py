"""Core ClamGuardian primitives."""

from .base import BaseAVEngine, BaseThreatProvider, ScanProgress, ScanResult, ScanStatus
from .errors import ClamGuardianError, EngineError, ProfileError
from .profiles import DEFAULT_PROFILE, DEFAULT_REGISTRY, ScanProfile, ScanProfileRegistry
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
    "ProfileError",
    "ScanProfile",
    "ScanProfileRegistry",
    "DEFAULT_PROFILE",
    "DEFAULT_REGISTRY",
    "QuarantineEntry",
    "QuarantineVault",
    "ScanTaskRunner",
]
