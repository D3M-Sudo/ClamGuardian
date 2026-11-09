"""Threat Intelligence orchestration with explicit API profile and upload consent."""
from __future__ import annotations

import logging
from typing import Any

from ..core.base import ScanResult
from ..core.settings import SettingsStore
from .profiles import APIProfile
from .secrets import IntelligenceSecretStore, SecretStorageError
from .upload import preview_upload, submit_after_consent
from .virustotal import VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED, VirusTotalProvider

logger = logging.getLogger(__name__)


class ThreatIntelligenceService:
    """Optional VirusTotal enrichment; never modifies the ClamAV verdict."""

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
        return self.settings_store.load().intelligence_enabled

    def selected_profile(self) -> APIProfile:
        return APIProfile.parse(self.settings_store.load().intelligence_profile)

    def get_provider(self) -> VirusTotalProvider | None:
        if not self.is_enabled():
            return None
        profile = self.selected_profile()
        if profile is APIProfile.PUBLIC and not VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED:
            return None
        if self._provider_initialized:
            return self._provider
        try:
            credential = self.secret_store.get_credential(profile)
            if not credential:
                logger.warning("Threat intelligence enabled but no credential configured for %s", profile.value)
                return None
            self._provider = VirusTotalProvider(credential, profile=profile)
            self._provider_initialized = True
            return self._provider
        except SecretStorageError:
            logger.error("Threat intelligence secure credential retrieval failed")
            return None

    async def lookup_scan_result(self, result: ScanResult) -> dict[str, Any] | None:
        if not self.is_enabled():
            return None
        sha256 = result.metadata.get("sha256")
        if not isinstance(sha256, str) or len(sha256) != 64:
            return None
        provider = self.get_provider()
        if provider is None:
            return None
        try:
            return await provider.lookup_hash(sha256)
        except Exception as exc:
            # Do not log or return raw upstream bodies, credentials, or file paths.
            logger.error("Threat intelligence lookup failed (%s)", type(exc).__name__)
            return {"provider": provider.name, "error": "VirusTotal lookup failed", "sha256": sha256}

    def preview_file_upload(self, path):
        if not self.is_enabled():
            raise PermissionError("Threat Intelligence must be enabled before upload")
        if self.get_provider() is None:
            raise PermissionError("Selected VirusTotal API profile is unavailable or blocked")
        return preview_upload(path)

    async def lookup_upload_candidate(self, preview) -> dict[str, Any]:
        provider = self.get_provider()
        if provider is None:
            raise PermissionError("Selected VirusTotal API profile is unavailable or blocked")
        return await provider.lookup_hash(preview.sha256)

    async def upload_file(
        self, preview, *, consent: bool, lookup_report: dict[str, Any]
    ) -> dict[str, Any]:
        if lookup_report.get("found") is not False:
            raise PermissionError(
                "File upload is permitted only after a successful hash lookup reports no existing file"
            )
        provider = self.get_provider()
        if provider is None:
            raise PermissionError("Selected VirusTotal API profile is unavailable or blocked")
        return await submit_after_consent(provider, preview, consent=consent)
