"""Threat Intelligence integration (Phase 11 / Phase 2, v1.2.0).

Provides optional, opt-in SHA-256 hash-only lookups (VirusTotal) with secure OS
Secret Service credential management and strict separation from local ClamAV
verdicts. Zero network requests occur when disabled.
"""

from .cache import VirusTotalCache
from .manager import ThreatProviderManager
from .secrets import IntelligenceSecretStore, SecretStorageError
from .service import ThreatIntelligenceService
from .virustotal import VirusTotalProvider

__all__ = [
    "IntelligenceSecretStore",
    "SecretStorageError",
    "ThreatIntelligenceService",
    "ThreatProviderManager",
    "VirusTotalProvider",
    "VirusTotalCache",
]
