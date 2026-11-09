"""VirusTotal v3 provider supporting explicitly selected Public and Premium profiles."""
from __future__ import annotations

import asyncio
import email.utils
import hashlib
import time
from pathlib import Path
from typing import Any

import aiohttp

from ..core.base import BaseThreatProvider
from .models import UploadPreview
from .profiles import APIProfile
from .rate_limiter import PersistentRateLimiter, QuotaExceeded
from .reports import normalize_analysis_report, normalize_file_report

# Public API network access remains blocked until written eligibility clarification
# is recorded by the maintainer. Premium is a separately licensed product profile.
VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED = False
MAX_UPLOAD_SIZE = 650 * 1024 * 1024
STANDARD_UPLOAD_SIZE = 32 * 1024 * 1024


class VirusTotalAPIError(RuntimeError):
    def __init__(self, status: int, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


class VirusTotalProvider(BaseThreatProvider):
    name = "virustotal"
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(
        self,
        api_key: str,
        *,
        profile: APIProfile | str = APIProfile.PUBLIC,
        timeout: float = 60.0,
        min_request_interval: float | None = None,
        rate_limit_path: Path | None = None,
        session_factory: Any | None = None,
    ) -> None:
        if not isinstance(api_key, str) or not api_key.strip():
            raise ValueError("VirusTotal API key is required")
        self._api_key = api_key.strip()
        self.profile = APIProfile.parse(profile)
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._limiter = PersistentRateLimiter(
            self.profile, state_path=rate_limit_path, min_interval=min_request_interval
        )
        self._rate_lock = asyncio.Lock()
        self._session_factory = session_factory or aiohttp.ClientSession
        self._min_interval = self._limiter.min_interval
        self._rate_limit_path = self._limiter.path

    def _reserve_rate_limit_slot(self) -> float:
        return self._limiter.reserve()

    async def _enforce_rate_limit(self) -> None:
        await self._reserve()

    async def _reserve(self) -> None:
        async with self._rate_lock:
            while True:
                remaining = await asyncio.to_thread(self._limiter.reserve)
                if remaining <= 0:
                    return
                await asyncio.sleep(remaining)

    @staticmethod
    def _retry_after(value: str | None) -> int | None:
        if not value:
            return None
        try:
            return max(0, int(value))
        except ValueError:
            try:
                parsed = email.utils.parsedate_to_datetime(value)
                return max(0, int(parsed.timestamp() - time.time()))
            except (TypeError, ValueError, OverflowError):
                return None

    async def _request(self, method: str, url: str, **kwargs: Any) -> dict[str, Any]:
        await self._reserve()
        headers = {"x-apikey": self._api_key, "accept": "application/json"}
        async with self._session_factory(timeout=self._timeout, headers=headers) as session:
            try:
                requester = getattr(session, method.lower(), None)
                if requester is None:
                    requester = lambda target, **options: session.request(method, target, **options)
                async with requester(url, **kwargs) as response:
                    if response.status == 404:
                        return {"_http_status": 404}
                    if response.status == 429:
                        retry = self._retry_after(response.headers.get("Retry-After"))
                        if retry:
                            await asyncio.to_thread(self._limiter.defer, retry)
                        raise VirusTotalAPIError(429, "VirusTotal API rate/quota limit reached", retry)
                    if response.status >= 400:
                        raise VirusTotalAPIError(
                            response.status, f"VirusTotal API request failed (HTTP {response.status})"
                        )
                    payload = await response.json()
                    if not isinstance(payload, dict):
                        raise RuntimeError("VirusTotal returned an invalid response")
                    return payload
            except (aiohttp.ClientError, TimeoutError) as exc:
                raise RuntimeError("VirusTotal network request failed or timed out") from exc

    def _ensure_profile_eligible(self) -> None:
        if self.profile is APIProfile.PUBLIC and not VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED:
            raise PermissionError(
                "VirusTotal Public API access is administratively blocked pending written eligibility authorization"
            )

    async def lookup_hash(self, sha256: str) -> dict[str, Any]:
        if len(sha256) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in sha256):
            raise ValueError("sha256 must be a 64-character hexadecimal digest")
        self._ensure_profile_eligible()
        digest = sha256.lower()
        payload = await self._request("GET", f"{self.BASE_URL}/files/{digest}")
        if payload.get("_http_status") == 404:
            return {"provider": self.name, "found": False, "sha256": digest}
        return normalize_file_report(payload, digest)

    async def upload_file(self, path: Path, expected_sha256: str) -> str:
        self._ensure_profile_eligible()
        """Upload a file after caller-side consent and TOCTOU validation."""
        path = Path(path)
        if not path.is_file():
            raise ValueError("Upload target must be a regular file")
        if path.stat().st_size > MAX_UPLOAD_SIZE:
            raise ValueError("VirusTotal file upload limit is 650 MiB")
        actual = await asyncio.to_thread(_sha256_file, path)
        if actual != expected_sha256.lower():
            raise RuntimeError("File changed after consent; upload cancelled")
        upload_url = f"{self.BASE_URL}/files"
        if path.stat().st_size > STANDARD_UPLOAD_SIZE:
            target = await self._request("GET", f"{self.BASE_URL}/files/upload_url")
            upload_url = target.get("data")
            if not isinstance(upload_url, str) or not upload_url.startswith("https://"):
                raise RuntimeError("VirusTotal did not return a valid one-time upload URL")
        await self._reserve()
        form = aiohttp.FormData()
        with path.open("rb") as handle:
            form.add_field("file", handle, filename=path.name, content_type="application/octet-stream")
            headers = {"x-apikey": self._api_key}
            async with self._session_factory(timeout=self._timeout, headers=headers) as session:
                try:
                    async with session.post(upload_url, data=form) as response:
                        if response.status == 429:
                            retry = self._retry_after(response.headers.get("Retry-After"))
                            if retry:
                                await asyncio.to_thread(self._limiter.defer, retry)
                            raise VirusTotalAPIError(
                                429, "VirusTotal upload rate/quota limit reached", retry
                            )
                        if response.status >= 400:
                            raise VirusTotalAPIError(response.status, f"VirusTotal upload failed (HTTP {response.status})")
                        payload = await response.json()
                except (aiohttp.ClientError, TimeoutError) as exc:
                    raise RuntimeError("VirusTotal upload failed or timed out") from exc
        if _sha256_file(path) != expected_sha256.lower():
            raise RuntimeError("File changed during upload; result must be treated as indeterminate")
        analysis_id = payload.get("data", {}).get("id")
        if not isinstance(analysis_id, str) or not analysis_id:
            raise RuntimeError("VirusTotal upload response did not include an analysis ID")
        return analysis_id

    async def get_analysis(self, analysis_id: str) -> dict[str, Any]:
        self._ensure_profile_eligible()
        if not analysis_id or "/" in analysis_id:
            raise ValueError("Invalid VirusTotal analysis identifier")
        payload = await self._request("GET", f"{self.BASE_URL}/analyses/{analysis_id}")
        return normalize_analysis_report(payload)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
