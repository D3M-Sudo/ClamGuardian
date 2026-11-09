"""VirusTotal v3 provider supporting explicitly selected Public and Premium profiles."""
from __future__ import annotations

import asyncio
import email.utils
import hashlib
import os
import stat
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import aiohttp

from ..core.base import BaseThreatProvider
from .profiles import APIProfile
from .rate_limiter import PersistentRateLimiter
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
        kwargs.setdefault("allow_redirects", False)
        async with self._session_factory(timeout=self._timeout, headers=headers) as session:
            try:
                requester = getattr(session, method.lower(), None)
                if requester is None:
                    def request_with_method(target, **options):
                        return session.request(method, target, **options)

                    requester = request_with_method
                async with requester(url, **kwargs) as response:
                    if response.status == 404:
                        return {"_http_status": 404}
                    if response.status == 429:
                        retry = self._retry_after(response.headers.get("Retry-After"))
                        if retry:
                            await asyncio.to_thread(self._limiter.defer, retry)
                        raise VirusTotalAPIError(
                            429, "VirusTotal API rate/quota limit reached", retry
                        )
                    if response.status >= 400:
                        raise VirusTotalAPIError(
                            response.status,
                            f"VirusTotal API request failed (HTTP {response.status})",
                        )
                    payload = await response.json()
                    if not isinstance(payload, dict):
                        raise RuntimeError("VirusTotal returned an invalid response")
                    return payload
            except (aiohttp.ClientError, TimeoutError) as exc:
                raise RuntimeError("VirusTotal network request failed or timed out") from exc

    def _ensure_profile_eligible(self) -> None:
        if (
            self.profile is APIProfile.PUBLIC
            and not VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED
        ):
            raise PermissionError(
                "VirusTotal Public API access is administratively blocked pending "
                "written eligibility authorization"
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

    async def upload_file(
        self, path: Path, expected_sha256: str, *, consent: bool
    ) -> str:
        """Upload only after explicit per-file consent and a fresh absent-hash lookup."""
        if consent is not True:
            raise PermissionError("Explicit per-file consent is required before upload")
        self._ensure_profile_eligible()
        if (
            not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64
            or any(ch not in "0123456789abcdefABCDEF" for ch in expected_sha256)
        ):
            raise ValueError("expected_sha256 must be a 64-character hexadecimal digest")
        existing = await self.lookup_hash(expected_sha256.lower())
        if existing.get("found") is not False:
            raise PermissionError(
                "Upload is allowed only when a fresh VirusTotal hash lookup "
                "reports no existing file"
            )

        target = Path(path)
        snapshot, size = await asyncio.to_thread(
            _create_upload_snapshot, target, expected_sha256.lower()
        )
        try:
            upload_url = f"{self.BASE_URL}/files"
            if size > STANDARD_UPLOAD_SIZE:
                response = await self._request("GET", f"{self.BASE_URL}/files/upload_url")
                upload_url = self._validate_upload_url(response.get("data"))

            await self._reserve()
            snapshot.seek(0)
            form = aiohttp.FormData()
            form.add_field(
                "file", snapshot, filename=target.name,
                content_type="application/octet-stream",
            )
            headers = {"x-apikey": self._api_key}
            async with self._session_factory(timeout=self._timeout, headers=headers) as session:
                try:
                    async with session.post(
                        upload_url, data=form, allow_redirects=False
                    ) as response:
                        if 300 <= response.status < 400:
                            raise VirusTotalAPIError(
                                response.status, "VirusTotal upload redirect refused"
                            )
                        if response.status == 429:
                            retry = self._retry_after(response.headers.get("Retry-After"))
                            if retry:
                                await asyncio.to_thread(self._limiter.defer, retry)
                            raise VirusTotalAPIError(
                                429, "VirusTotal upload rate/quota limit reached", retry
                            )
                        if response.status >= 400:
                            raise VirusTotalAPIError(
                                response.status,
                                f"VirusTotal upload failed (HTTP {response.status})",
                            )
                        payload = await response.json()
                except (aiohttp.ClientError, TimeoutError) as exc:
                    raise RuntimeError("VirusTotal upload failed or timed out") from exc

            snapshot.seek(0)
            snapshot_digest = await asyncio.to_thread(_sha256_fileobj, snapshot)
            if snapshot_digest != expected_sha256.lower():
                raise RuntimeError("Upload snapshot changed during transmission; result is indeterminate")
            data = payload.get("data") if isinstance(payload, dict) else None
            analysis_id = data.get("id") if isinstance(data, dict) else None
            if not isinstance(analysis_id, str) or not analysis_id:
                raise RuntimeError("VirusTotal upload response did not include an analysis ID")
            return analysis_id
        finally:
            snapshot.close()

    @staticmethod
    def _validate_upload_url(value: Any) -> str:
        if not isinstance(value, str):
            raise RuntimeError("VirusTotal did not return a valid one-time upload URL")
        parsed = urlsplit(value)
        try:
            port = parsed.port
        except ValueError as exc:
            raise RuntimeError("VirusTotal returned an unsafe upload URL") from exc
        if (
            parsed.scheme != "https"
            or parsed.hostname != "www.virustotal.com"
            or parsed.username is not None
            or parsed.password is not None
            or port not in (None, 443)
            or parsed.path != "/api/v3/files"
            or parsed.fragment
        ):
            raise RuntimeError("VirusTotal returned an unsafe upload URL; refusing transmission")
        return value

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


def _create_upload_snapshot(path: Path, expected_sha256: str):
    """Create a private, unlinked snapshot from a stable regular-file descriptor."""
    target = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    source_fd = os.open(target, flags)
    try:
        snapshot = tempfile.TemporaryFile(mode="w+b")  # noqa: SIM115 - caller closes it
    except BaseException:
        os.close(source_fd)
        raise
    try:
        with os.fdopen(source_fd, "rb", closefd=False) as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("Upload target must be a regular file")
            if before.st_size > MAX_UPLOAD_SIZE:
                raise ValueError("VirusTotal file upload limit is 650 MiB")
            digest = hashlib.sha256()
            total = 0
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                total += len(chunk)
                if total > MAX_UPLOAD_SIZE:
                    raise ValueError("VirusTotal file upload limit is 650 MiB")
                digest.update(chunk)
                snapshot.write(chunk)
            after = os.fstat(source.fileno())
            before_state = (
                before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns,
            )
            after_state = (
                after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns,
            )
            if before_state != after_state or total != before.st_size:
                raise RuntimeError("File changed while preparing the upload snapshot")
            if digest.hexdigest() != expected_sha256:
                raise RuntimeError("File changed after consent; upload cancelled")
        snapshot.flush()
        snapshot.seek(0)
        return snapshot, total
    except BaseException:
        snapshot.close()
        raise
    finally:
        os.close(source_fd)


def _sha256_fileobj(handle) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()
