"""VirusTotal v3 provider supporting explicitly selected Public and Premium profiles."""
from __future__ import annotations

import asyncio
import email.utils
import hashlib
import os
import socket
import stat
import tempfile
import threading
import time
from contextlib import suppress
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
_DNS_THREAD_SLOTS = threading.BoundedSemaphore(4)


class _BoundedDaemonResolver(aiohttp.abc.AbstractResolver):
    """Resolve DNS without the asyncio default executor.

    getaddrinfo is blocking on some Linux resolver configurations. Isolate it
    in a daemon thread with a process-wide concurrency cap so a stuck NSS/DNS
    lookup cannot hold the service-owned event loop or its shutdown hostage.
    """

    def __init__(self, timeout: float = 5.0) -> None:
        self._timeout = timeout
        self._closed = False

    async def resolve(
        self, host: str, port: int = 0, family: int = socket.AF_INET
    ) -> list[dict[str, Any]]:
        if self._closed:
            raise OSError("DNS resolver is closed")
        if not _DNS_THREAD_SLOTS.acquire(blocking=False):
            raise OSError(socket.EAI_AGAIN, "DNS resolver concurrency limit reached")

        loop = asyncio.get_running_loop()
        result_future: asyncio.Future[list[aiohttp.abc.ResolveResult]] = (
            loop.create_future()
        )

        def deliver(
            result: list[aiohttp.abc.ResolveResult] | None = None,
            error: OSError | None = None,
        ) -> None:
            def complete() -> None:
                if result_future.done():
                    return
                if error is not None:
                    result_future.set_exception(error)
                else:
                    result_future.set_result(result or [])

            # The awaiting loop may have been closed after cancellation.
            with suppress(RuntimeError):
                loop.call_soon_threadsafe(complete)

        def resolve_blocking() -> None:
            try:
                records = socket.getaddrinfo(
                    host, port, family=family, type=socket.SOCK_STREAM
                )
                addresses: list[aiohttp.abc.ResolveResult] = [
                    {
                        "hostname": host,
                        "host": record[4][0],
                        "port": record[4][1],
                        "family": record[0],
                        "proto": record[2],
                        "flags": record[3],
                    }
                    for record in records
                ]
                if not addresses:
                    deliver(error=OSError(socket.EAI_NONAME, "DNS returned no addresses"))
                else:
                    deliver(result=addresses)
            except OSError as exc:
                deliver(error=exc)
            except Exception as exc:
                deliver(error=OSError(f"DNS resolution failed: {type(exc).__name__}"))
            finally:
                _DNS_THREAD_SLOTS.release()

        thread = threading.Thread(
            target=resolve_blocking,
            name="clamguardian-vt-dns",
            daemon=True,
        )
        try:
            thread.start()
        except Exception:
            _DNS_THREAD_SLOTS.release()
            raise

        try:
            return await asyncio.wait_for(result_future, timeout=self._timeout)
        except TimeoutError:
            raise OSError(socket.EAI_AGAIN, "DNS resolution timed out") from None

    def close(self) -> None:
        self._closed = True


class VirusTotalTransientError(RuntimeError):
    """A temporary transport or server failure eligible for bounded retry."""


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
        # Provider instances may be shared by async callers on different
        # event loops. asyncio.Lock is loop-affine; this lock is deliberately
        # acquired non-blockingly and polled so it is safe across loops.
        self._rate_lock = threading.Lock()
        # Tests and embedders may inject a session factory. Production sessions
        # use the bounded resolver above instead of aiohttp's executor-backed
        # ThreadedResolver.
        self._session_factory = session_factory
        self._min_interval = self._limiter.min_interval
        self._rate_limit_path = self._limiter.path

    def _reserve_rate_limit_slot(self) -> float:
        return self._limiter.reserve()

    async def _enforce_rate_limit(self) -> None:
        await self._reserve()

    async def _reserve(self) -> None:
        while not self._rate_lock.acquire(blocking=False):
            await asyncio.sleep(0.01)
        try:
            while True:
                # The cross-loop lock serializes this bounded (2s lock wait)
                # local state operation. Do not create a worker-executor thread.
                remaining = self._limiter.reserve()
                if remaining <= 0:
                    return
                await asyncio.sleep(remaining)
        finally:
            self._rate_lock.release()

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
        if self._session_factory is None:
            resolver = _BoundedDaemonResolver(timeout=5.0)
            connector = aiohttp.TCPConnector(resolver=resolver, ttl_dns_cache=10)
            session_context = aiohttp.ClientSession(
                timeout=self._timeout,
                headers=headers,
                connector=connector,
            )
        else:
            session_context = self._session_factory(
                timeout=self._timeout, headers=headers
            )
        async with session_context as session:
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
                            self._limiter.defer(retry)
                        raise VirusTotalAPIError(
                            429, "VirusTotal API rate/quota limit reached", retry
                        )
                    if response.status >= 500 or response.status in (408, 425):
                        raise VirusTotalTransientError(
                            f"VirusTotal temporary API failure (HTTP {response.status})"
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
                raise VirusTotalTransientError(
                    "VirusTotal network request failed or timed out"
                ) from exc

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
                upload_url_response = await self._request(
                    "GET", f"{self.BASE_URL}/files/upload_url"
                )
                upload_url = self._validate_upload_url(
                    upload_url_response.get("data")
                )

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
                raise RuntimeError(
                    "Upload snapshot changed during transmission; result is indeterminate"
                )
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
