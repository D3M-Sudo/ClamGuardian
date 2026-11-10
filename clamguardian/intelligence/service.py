"""Threat Intelligence orchestration with cache, bounded retries and upload consent."""
from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import threading
import time
from typing import Any

from ..core.base import ScanResult
from ..core.settings import SettingsStore
from .cache import VirusTotalCache
from .profiles import APIProfile
from .secrets import IntelligenceSecretStore, SecretStorageError
from .upload import preview_upload, submit_after_consent
from .virustotal import (
    VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED,
    VirusTotalAPIError,
    VirusTotalProvider,
    VirusTotalTransientError,
)

logger = logging.getLogger(__name__)

_MAX_LOOKUP_ATTEMPTS = 3
_RETRY_BASE_SECONDS = 1.0
_RETRY_MAX_SECONDS = 8.0


class ThreatIntelligenceService:
    """Optional VirusTotal enrichment; never modifies the ClamAV verdict."""

    def __init__(
        self,
        settings_store: SettingsStore | None = None,
        secret_store: IntelligenceSecretStore | None = None,
        provider: VirusTotalProvider | None = None,
        cache: VirusTotalCache | None = None,
    ) -> None:
        self.settings_store = settings_store or SettingsStore()
        self.secret_store = secret_store or IntelligenceSecretStore()
        self._custom_provider = provider
        self._provider: VirusTotalProvider | None = provider
        self._provider_initialized = provider is not None
        self.cache = cache or VirusTotalCache(
            self.settings_store.path.with_name("virustotal-cache.db")
        )
        self._inflight: dict[
            tuple[str, str], concurrent.futures.Future[dict[str, Any]]
        ] = {}
        self._inflight_lock = threading.Lock()
        self._upload_lookup: tuple[str, str, dict[str, Any], float] | None = None

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
        if (
            self._provider_initialized
            and self._custom_provider is None
            and self._provider is not None
            and getattr(self._provider, "profile", profile) is not profile
        ):
            self._provider = None
            self._provider_initialized = False
            self._upload_lookup = None
        if self._provider_initialized:
            return self._provider
        try:
            credential = self.secret_store.get_credential(profile)
            if not credential:
                logger.warning(
                    "Threat intelligence enabled but no credential configured for %s",
                    profile.value,
                )
                return None
            self._provider = VirusTotalProvider(credential, profile=profile)
            self._provider_initialized = True
            return self._provider
        except SecretStorageError:
            logger.error("Threat intelligence secure credential retrieval failed")
            return None

    async def _lookup_with_retry(
        self, provider: VirusTotalProvider, sha256: str
    ) -> dict[str, Any]:
        for attempt in range(_MAX_LOOKUP_ATTEMPTS):
            try:
                return await provider.lookup_hash(sha256)
            except VirusTotalAPIError as exc:
                retryable = exc.status == 429 or 500 <= exc.status <= 599
                if not retryable or attempt + 1 >= _MAX_LOOKUP_ATTEMPTS:
                    raise
                delay = (
                    float(exc.retry_after)
                    if exc.retry_after is not None
                    else min(_RETRY_BASE_SECONDS * (2**attempt), _RETRY_MAX_SECONDS)
                )
            except VirusTotalTransientError:
                if attempt + 1 >= _MAX_LOOKUP_ATTEMPTS:
                    raise
                delay = min(_RETRY_BASE_SECONDS * (2**attempt), _RETRY_MAX_SECONDS)
            await asyncio.sleep(max(0.0, delay))
        raise RuntimeError("VirusTotal lookup retry loop exhausted")

    async def lookup_scan_result(self, result: ScanResult) -> dict[str, Any] | None:
        if not self.is_enabled():
            return None
        sha256 = result.metadata.get("sha256")
        if (
            not isinstance(sha256, str)
            or len(sha256) != 64
            or any(ch not in "0123456789abcdefABCDEF" for ch in sha256)
        ):
            return None
        digest = sha256.lower()
        selected_profile = self.selected_profile()
        if (
            selected_profile is APIProfile.PUBLIC
            and not VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED
        ):
            return None
        profile = selected_profile.value

        # A valid, unexpired report can be reused offline; cache access does
        # not require the API credential to be present or reachable.
        try:
            cached = await asyncio.to_thread(self.cache.get, digest, profile)
        except Exception as exc:
            logger.warning("VirusTotal cache read failed (%s)", type(exc).__name__)
            cached = None
        if cached is not None:
            return cached

        provider = self.get_provider()
        if provider is None:
            return None
        if (
            self._custom_provider is None
            and getattr(provider, "profile", selected_profile) is not selected_profile
        ):
            return None

        key = (digest, profile)
        with self._inflight_lock:
            shared = self._inflight.get(key)
            leader = shared is None
            if shared is None:
                shared = concurrent.futures.Future()
                self._inflight[key] = shared

        if not leader:
            return await asyncio.shield(asyncio.wrap_future(shared))

        try:
            report = await self._lookup_with_retry(provider, digest)
            if (
                isinstance(report, dict)
                and report.get("error") is None
                and isinstance(report.get("found"), bool)
            ):
                try:
                    await asyncio.to_thread(self.cache.put, digest, profile, report)
                except Exception as exc:
                    logger.warning("VirusTotal cache write failed (%s)", type(exc).__name__)
            shared.set_result(report)
            return report
        except asyncio.CancelledError:
            shared.set_result(
                {
                    "provider": provider.name,
                    "error": "VirusTotal lookup cancelled",
                    "sha256": digest,
                }
            )
            raise
        except Exception as exc:
            logger.error("Threat intelligence lookup failed (%s)", type(exc).__name__)
            report = {
                "provider": provider.name,
                "error": "VirusTotal lookup failed",
                "sha256": digest,
            }
            shared.set_result(report)
            return report
        finally:
            with self._inflight_lock:
                if self._inflight.get(key) is shared:
                    self._inflight.pop(key, None)

    def preview_file_upload(self, path):
        self._upload_lookup = None
        if not self.is_enabled():
            raise PermissionError("Threat Intelligence must be enabled before upload")
        if self.get_provider() is None:
            raise PermissionError("Selected VirusTotal API profile is unavailable or blocked")
        return preview_upload(path)

    async def lookup_upload_candidate(self, preview) -> dict[str, Any]:
        self._upload_lookup = None
        provider = self.get_provider()
        if provider is None:
            raise PermissionError("Selected VirusTotal API profile is unavailable or blocked")
        report = await self._lookup_with_retry(provider, preview.sha256)
        self._upload_lookup = (
            preview.sha256,
            self.selected_profile().value,
            report,
            time.monotonic(),
        )
        return report

    async def upload_file(
        self, preview, *, consent: bool, lookup_report: dict[str, Any]
    ) -> dict[str, Any]:
        if consent is not True:
            raise PermissionError("Explicit per-file consent is required before upload")
        cached = self._upload_lookup
        if (
            cached is None
            or cached[0] != preview.sha256
            or cached[1] != self.selected_profile().value
            or time.monotonic() - cached[3] > 300
            or cached[2].get("found") is not False
            or not isinstance(lookup_report, dict)
            or lookup_report.get("found") is not False
        ):
            raise PermissionError(
                "Upload requires a recent successful hash lookup for this exact "
                "file and API profile"
            )
        self._upload_lookup = None
        provider = self.get_provider()
        if provider is None:
            raise PermissionError("Selected VirusTotal API profile is unavailable or blocked")
        return await submit_after_consent(provider, preview, consent=True)
