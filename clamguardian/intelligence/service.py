"""Threat Intelligence orchestration with cache, bounded retries and upload consent."""
from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import copy
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
_asyncio_sleep = asyncio.sleep

_MAX_LOOKUP_ATTEMPTS = 3
_RETRY_BASE_SECONDS = 1.0
_RETRY_MAX_SECONDS = 8.0


class _ServiceOwnedEventLoop:
    """A private asyncio loop whose lifetime is independent of lookup callers."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._ready = threading.Event()
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._closed = False

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        with self._lock:
            self._loop = loop
            should_run = not self._closed
            if should_run:
                # This callback runs only after run_forever() has entered its
                # running state. Signalling before run_forever() creates a
                # startup window in which submit() sees is_running() == False.
                loop.call_soon(self._ready.set)
            else:
                self._ready.set()

        if not should_run:
            loop.close()
            return

        try:
            loop.run_forever()
        finally:
            # Always release submitters if startup or the loop itself fails.
            self._ready.set()
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(
                    asyncio.gather(*pending, return_exceptions=True)
                )
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.run_until_complete(loop.shutdown_default_executor())
            loop.close()

    def submit(self, coroutine: Any) -> concurrent.futures.Future[Any]:
        with self._lock:
            if self._closed:
                coroutine.close()
                raise RuntimeError("Threat Intelligence service is closed")
            if self._thread is None:
                self._thread = threading.Thread(
                    target=self._run,
                    name="clamguardian-intelligence",
                    daemon=True,
                )
                self._thread.start()

        # Do not hold _lock while waiting: the worker needs it to publish its
        # loop. The second locked section closes the race with close().
        if not self._ready.wait(timeout=5):
            coroutine.close()
            self.close(timeout=0.1)
            raise RuntimeError("Threat Intelligence event loop did not start")

        with self._lock:
            if self._closed:
                coroutine.close()
                raise RuntimeError("Threat Intelligence service is closed")
            loop = self._loop
            if loop is None or loop.is_closed() or not loop.is_running():
                coroutine.close()
                raise RuntimeError("Threat Intelligence event loop is unavailable")
            try:
                return asyncio.run_coroutine_threadsafe(coroutine, loop)
            except RuntimeError:
                coroutine.close()
                raise

    async def submit_async(self, coroutine: Any) -> concurrent.futures.Future[Any]:
        """Submit without blocking the caller's event loop during worker startup."""
        with self._lock:
            if self._closed:
                coroutine.close()
                raise RuntimeError("Threat Intelligence service is closed")
            if self._thread is None:
                self._thread = threading.Thread(
                    target=self._run,
                    name="clamguardian-intelligence",
                    daemon=True,
                )
                self._thread.start()

        try:
            while not self._ready.is_set():
                with self._lock:
                    if self._closed:
                        coroutine.close()
                        raise RuntimeError("Threat Intelligence service is closed")
                await _asyncio_sleep(0.005)
            return self.submit(coroutine)
        except BaseException:
            coroutine.close()
            raise

    def close(self, timeout: float = 3.0) -> None:
        with self._lock:
            self._closed = True
            loop = self._loop
            thread = self._thread

        if loop is not None and not loop.is_closed():
            if loop.is_running():
                async def cancel_pending() -> None:
                    current = asyncio.current_task()
                    pending = [
                        task for task in asyncio.all_tasks()
                        if task is not current
                    ]
                    for task in pending:
                        task.cancel()
                    if pending:
                        await asyncio.gather(*pending, return_exceptions=True)

                try:
                    shutdown = asyncio.run_coroutine_threadsafe(cancel_pending(), loop)
                    shutdown.result(timeout=max(0.1, timeout))
                except Exception:
                    logger.warning(
                        "Threat Intelligence event-loop tasks did not drain cleanly"
                    )

            # Also signal stop when the thread has published its loop but has
            # not entered run_forever() yet. The queued stop is consumed as
            # soon as run_forever() starts.
            with contextlib.suppress(RuntimeError):
                loop.call_soon_threadsafe(loop.stop)

        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.1, timeout))
            if thread.is_alive():
                logger.warning("Threat Intelligence event-loop thread did not stop")

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
        self._provider_lock = threading.RLock()
        self._lookup_loop = _ServiceOwnedEventLoop()
        try:
            self.cache: VirusTotalCache | None = cache or VirusTotalCache(
                self.settings_store.path.with_name("virustotal-cache.db")
            )
        except Exception as exc:
            self.cache = None
            logger.warning(
                "VirusTotal cache initialization failed (%s); continuing without cache",
                type(exc).__name__,
            )
        self._inflight: dict[
            tuple[str, str], concurrent.futures.Future[dict[str, Any]]
        ] = {}
        # Strong references keep service-owned tasks alive independently of
        # whichever caller happened to create the shared lookup.
        self._lookup_tasks: dict[
            tuple[str, str], concurrent.futures.Future[None]
        ] = {}
        self._inflight_lock = threading.Lock()
        self._cache_writes: dict[tuple[str, str], concurrent.futures.Future[Any]] = {}
        self._upload_lookup: tuple[str, str, dict[str, Any], float] | None = None
        # One daemon worker bounds cache I/O without blocking either asyncio
        # loop or creating threads in asyncio's default executor.
        self._cache_worker_slots = threading.BoundedSemaphore(1)

    def close(self, timeout: float = 8.0) -> None:
        """Drain shared lookups and stop the service-owned worker loop."""
        deadline = time.monotonic() + max(0.1, timeout)
        with self._inflight_lock:
            tasks = tuple(self._lookup_tasks.values())
        for task in tasks:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                task.result(timeout=remaining)
            except concurrent.futures.TimeoutError:
                task.cancel()
            except concurrent.futures.CancelledError:
                pass
            except Exception:
                logger.warning("Threat Intelligence lookup task ended unexpectedly")
        self._lookup_loop.close(timeout=max(0.1, deadline - time.monotonic()))
        with self._inflight_lock:
            for shared in self._inflight.values():
                if not shared.done():
                    shared.set_result({
                        "provider": "virustotal",
                        "error": "VirusTotal lookup cancelled",
                    })
            self._inflight.clear()
            self._lookup_tasks.clear()

    def is_enabled(self) -> bool:
        return self.settings_store.load().intelligence_enabled

    def selected_profile(self) -> APIProfile:
        return APIProfile.parse(self.settings_store.load().intelligence_profile)

    def get_provider(self) -> VirusTotalProvider | None:
        with self._provider_lock:
            if not self.is_enabled():
                return None
            profile = self.selected_profile()
            if (
                profile is APIProfile.PUBLIC
                and not VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED
            ):
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

    def _schedule_cache_operation(
        self, label: str, operation: Any, *args: Any
    ) -> concurrent.futures.Future[Any] | None:
        if self.cache is None or not self._cache_worker_slots.acquire(blocking=False):
            return None
        completed: concurrent.futures.Future[Any] = concurrent.futures.Future()

        def run() -> None:
            try:
                completed.set_result(operation(*args))
            except Exception as exc:
                logger.warning("VirusTotal cache %s failed (%s)", label, type(exc).__name__)
                completed.set_result(None)
            finally:
                self._cache_worker_slots.release()

        worker = threading.Thread(
            target=run, name="clamguardian-intelligence-cache", daemon=True
        )
        try:
            worker.start()
        except Exception as exc:
            self._cache_worker_slots.release()
            logger.warning("VirusTotal cache %s worker failed (%s)", label, type(exc).__name__)
            completed.set_result(None)
        return completed

    def _publish_shared_result(
        self,
        key: tuple[str, str],
        shared: concurrent.futures.Future[dict[str, Any]],
        report: dict[str, Any],
        *,
        keep_until: concurrent.futures.Future[Any] | None = None,
    ) -> None:
        # Keep the completed result joinable until its cache write finishes.
        # A caller whose cache read began just before that write was queued
        # must not start a duplicate provider request after the lookup ends.
        with self._inflight_lock:
            self._lookup_tasks.pop(key, None)
            if (
                self._inflight.get(key) is shared
                and (keep_until is None or keep_until.done())
            ):
                self._inflight.pop(key, None)
            publish = not shared.done()

        if publish:
            shared.set_result(report)

        if keep_until is not None and not keep_until.done():
            def forget_after_write(
                completed: concurrent.futures.Future[Any],
            ) -> None:
                with self._inflight_lock:
                    if self._inflight.get(key) is shared:
                        self._inflight.pop(key, None)

            keep_until.add_done_callback(forget_after_write)

    def _track_cache_write(
        self, key: tuple[str, str], operation: concurrent.futures.Future[Any]
    ) -> None:
        with self._inflight_lock:
            self._cache_writes[key] = operation

        def forget(completed: concurrent.futures.Future[Any]) -> None:
            with self._inflight_lock:
                if self._cache_writes.get(key) is completed:
                    self._cache_writes.pop(key, None)

        operation.add_done_callback(forget)

    async def _wait_for_cache_write(self, key: tuple[str, str]) -> None:
        with self._inflight_lock:
            operation = self._cache_writes.get(key)
        if operation is not None:
            await asyncio.shield(asyncio.wrap_future(operation))

    async def _read_cached_report(
        self, digest: str, profile: str
    ) -> dict[str, Any] | None:
        if self.cache is None:
            return None
        await self._wait_for_cache_write((digest, profile))
        operation = self._schedule_cache_operation("read", self.cache.get, digest, profile)
        if operation is None:
            return None
        result = await asyncio.shield(asyncio.wrap_future(operation))
        return result if isinstance(result, dict) else None

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
                if exc.retry_after is not None:
                    delay = float(exc.retry_after)
                    if delay > _RETRY_MAX_SECONDS:
                        raise
                    delay = max(0.0, delay)
                else:
                    delay = min(
                        _RETRY_BASE_SECONDS * (2**attempt), _RETRY_MAX_SECONDS
                    )
            except VirusTotalTransientError:
                if attempt + 1 >= _MAX_LOOKUP_ATTEMPTS:
                    raise
                delay = min(_RETRY_BASE_SECONDS * (2**attempt), _RETRY_MAX_SECONDS)
            await asyncio.sleep(max(0.0, delay))
        raise RuntimeError("VirusTotal lookup retry loop exhausted")

    async def _run_shared_lookup(
        self,
        key: tuple[str, str],
        shared: concurrent.futures.Future[dict[str, Any]],
        provider: VirusTotalProvider,
        digest: str,
        profile: str,
    ) -> None:
        """Run a deduplicated lookup under service, not caller, ownership."""
        try:
            report = await self._lookup_with_retry(provider, digest)
            # Publish the result before best-effort cache persistence. A locked
            # SQLite database must not delay callers after the network lookup.
            if (
                isinstance(report, dict)
                and report.get("error") is None
                and isinstance(report.get("found"), bool)
                and self.cache is not None
            ):
                cache_write = self._schedule_cache_operation(
                    "write", self.cache.put, digest, profile, report
                )
                if cache_write is not None:
                    self._track_cache_write(key, cache_write)
            self._publish_shared_result(
                key, shared, report, keep_until=cache_write if (
                    isinstance(report, dict)
                    and report.get("error") is None
                    and isinstance(report.get("found"), bool)
                    and self.cache is not None
                ) else None
            )
        except asyncio.CancelledError:
            # Cancellation of the owning event loop is exceptional (normal
            # caller cancellation is shielded below); still release waiters.
            self._publish_shared_result(key, shared, {
                "provider": provider.name,
                "error": "VirusTotal lookup cancelled",
                "sha256": digest,
            })
            raise
        except Exception as exc:
            logger.error("Threat intelligence lookup failed (%s)", type(exc).__name__)
            self._publish_shared_result(key, shared, {
                "provider": provider.name,
                "error": "VirusTotal lookup failed",
                "sha256": digest,
            })
        finally:
            with self._inflight_lock:
                # Successful lookups with cache persistence stay joinable
                # until the write callback removes them.
                if self._inflight.get(key) is shared and shared.done():
                    self._lookup_tasks.pop(key, None)

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
        key = (digest, profile)
        with self._inflight_lock:
            shared = self._inflight.get(key)

        if shared is None and self.cache is not None:
            cached = await self._read_cached_report(digest, profile)
            if cached is not None:
                return copy.deepcopy(cached)
            # Close the race where the first cache read started before an
            # in-flight lookup queued its persistence operation.
            with self._inflight_lock:
                shared = self._inflight.get(key)
            if shared is None:
                cached = await self._read_cached_report(digest, profile)
                if cached is not None:
                    return copy.deepcopy(cached)

        provider = self.get_provider()
        if provider is None:
            return None
        if (
            self._custom_provider is None
            and getattr(provider, "profile", selected_profile) is not selected_profile
        ):
            return None

        created = False
        with self._inflight_lock:
            shared = self._inflight.get(key)
            if shared is None:
                shared = concurrent.futures.Future()
                self._inflight[key] = shared
                created = True

        if created:
            try:
                task = await self._lookup_loop.submit_async(
                    self._run_shared_lookup(key, shared, provider, digest, profile)
                )
            except asyncio.CancelledError:
                with self._inflight_lock:
                    if self._inflight.get(key) is shared:
                        self._inflight.pop(key, None)
                if not shared.done():
                    shared.set_result({
                        "provider": provider.name,
                        "error": "VirusTotal lookup cancelled",
                        "sha256": digest,
                    })
                raise
            except RuntimeError:
                with self._inflight_lock:
                    if self._inflight.get(key) is shared:
                        self._inflight.pop(key, None)
                if not shared.done():
                    shared.set_result({
                        "provider": provider.name,
                        "error": "VirusTotal lookup failed",
                        "sha256": digest,
                    })
            else:
                with self._inflight_lock:
                    # The worker may finish before submit_async returns.
                    if not shared.done():
                        self._lookup_tasks[key] = task

        # Each waiter receives its own mutable report object. Cancelling one
        # waiter cannot cancel the service-owned shared lookup.
        report = await asyncio.shield(asyncio.wrap_future(shared))
        return copy.deepcopy(report)

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
        stored_report = copy.deepcopy(report)
        self._upload_lookup = (
            preview.sha256,
            self.selected_profile().value,
            stored_report,
            time.monotonic(),
        )
        return copy.deepcopy(stored_report)

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
            or lookup_report != cached[2]
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
