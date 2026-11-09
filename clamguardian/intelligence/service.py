"""Threat Intelligence service integration for ClamGuardian."""

from __future__ import annotations

import logging
from typing import Any

from ..core.base import ScanResult
from ..core.settings import SettingsStore
from .secrets import IntelligenceSecretStore, SecretStorageError
from .virustotal import VirusTotalProvider

logger = logging.getLogger(__name__)


class ThreatIntelligenceService:
    """Orchestrate optional, opt-in hash-only threat intelligence lookups."""

    def __init__(
        self,
        settings_store: SettingsStore | None = None,
        secret_store: IntelligenceSecretStore | None = None,
        provider: VirusTotalProvider | None = None,
    ) -> None:
        self.settings_store = settings_store or SettingsStore()
        self.secret_store = secret_store or IntelligenceSecretStore()
        self._custom_provider = provider
        self._provider: VirusTotalProvider | None = provider
        self._provider_initialized = provider is not None

    def is_enabled(self) -> bool:
        """Return whether threat intelligence is enabled by user preference."""
        return self.settings_store.load().intelligence_enabled

    def get_provider(self) -> VirusTotalProvider | None:
        """Return initialized provider if enabled and credentials exist, else None."""
        if not self.is_enabled():
            return None
        if not self.is_enabled():
            return None
        if self._provider_initialized:
            return self._provider
        self._provider_initialized = True
        try:
            api_key = self.secret_store.get_api_key()
            if not api_key:
                logger.warning("Threat intelligence enabled but no API key configured.")
                return None
            self._provider = VirusTotalProvider(api_key)
            return self._provider
        except SecretStorageError as exc:
            logger.error("Threat intelligence secret retrieval failed: %s", exc)
            return None

    async def lookup_scan_result(self, result: ScanResult) -> dict[str, Any] | None:
        """Query threat intelligence for single-file scan results with a valid SHA-256 digest.

        Guarantees:
        - If disabled: ZERO network requests.
        - Directory scans (sha256 is None): no request.
        - Never overrides or alters the local ClamAV scan result.
        """
        if not self.is_enabled():
            return None

        sha256 = result.metadata.get("sha256")
        if not sha256 or not isinstance(sha256, str):
            return None

        provider = self.get_provider()
        if provider is None:
            return None

        try:
            report = await provider.lookup_hash(sha256)
            return report
        except Exception as exc:
            logger.error("Threat intelligence lookup error for hash %s: %s", sha256, exc)
            return {
                "provider": provider.name,
                "error": str(exc),
                "sha256": sha256,
            }
