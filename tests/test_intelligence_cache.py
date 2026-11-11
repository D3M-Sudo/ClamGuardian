"""Persistent VirusTotal cache and shared lookup-service regression tests."""

from __future__ import annotations

import asyncio
import fcntl
import os
import socket
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import AsyncMock

import pytest

from clamguardian.core.base import ScanResult
from clamguardian.core.settings import AppSettings, SettingsStore
from clamguardian.intelligence import service as service_module
from clamguardian.intelligence import virustotal as virustotal_module
from clamguardian.intelligence.cache import VirusTotalCache
from clamguardian.intelligence.rate_limiter import PersistentRateLimiter
from clamguardian.intelligence.service import ThreatIntelligenceService
from clamguardian.intelligence.virustotal import (
    VirusTotalAPIError,
    VirusTotalProvider,
    VirusTotalTransientError,
)

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
REPORT = {
    "provider": "virustotal",
    "found": True,
    "sha256": SHA256,
    "last_analysis_stats": {"malicious": 0, "harmless": 12},
}


def test_cache_round_trip_and_profile_isolation(tmp_path) -> None:
    cache = VirusTotalCache(tmp_path / "vt.db")
    cache.put(SHA256, "public", REPORT)

    assert cache.get(SHA256, "public") == REPORT
    assert cache.get(SHA256, "premium") is None


def test_cache_expires_from_acquisition_time(tmp_path) -> None:
    now = [1000.0]
    cache = VirusTotalCache(tmp_path / "vt.db", ttl_seconds=60, clock=lambda: now[0])
    cache.put(SHA256, "public", REPORT)

    now[0] = 1059.999
    assert cache.get(SHA256, "public") == REPORT
    now[0] = 1060.0
    assert cache.get(SHA256, "public") is None


def test_cache_does_not_store_transient_failures(tmp_path) -> None:
    cache = VirusTotalCache(tmp_path / "vt.db")
    cache.put(
        SHA256,
        "public",
        {"provider": "virustotal", "sha256": SHA256, "error": "temporary failure"},
    )
    assert cache.get(SHA256, "public") is None


def test_cache_validates_hash_profile_and_ttl(tmp_path) -> None:
    with pytest.raises(ValueError, match="64-character"):
        VirusTotalCache(tmp_path / "bad.db").get("not-a-hash", "public")
    cache = VirusTotalCache(tmp_path / "vt.db")
    with pytest.raises(ValueError, match="profile"):
        cache.get(SHA256, "unknown")
    with pytest.raises(ValueError, match="positive finite"):
        VirusTotalCache(tmp_path / "invalid.db", ttl_seconds=float("inf"))


def test_cache_database_is_owner_only(tmp_path) -> None:
    cache = VirusTotalCache(tmp_path / "vt.db")
    assert cache.path.stat().st_mode & 0o777 == 0o600


@pytest.mark.asyncio
async def test_service_uses_persistent_cache_for_repeated_hashes(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        service_module, "VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED", True
    )
    settings = SettingsStore(tmp_path / "settings.json")
    settings.save(AppSettings(intelligence_enabled=True, intelligence_profile="public"))
    provider = AsyncMock(spec=VirusTotalProvider)
    provider.lookup_hash.return_value = REPORT
    service = ThreatIntelligenceService(
        settings_store=settings,
        provider=provider,
        cache=VirusTotalCache(tmp_path / "vt.db"),
    )
    result = ScanResult(target="/sample", clean=True, metadata={"sha256": SHA256})

    assert await service.lookup_scan_result(result) == REPORT
    assert await service.lookup_scan_result(result) == REPORT
    provider.lookup_hash.assert_awaited_once_with(SHA256)
    assert service._lookup_loop._loop is not None
    assert service._lookup_loop._loop._default_executor is None
    service.close()


@pytest.mark.asyncio
async def test_service_deduplicates_concurrent_lookups(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        service_module, "VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED", True
    )
    settings = SettingsStore(tmp_path / "settings.json")
    settings.save(AppSettings(intelligence_enabled=True, intelligence_profile="public"))
    provider = AsyncMock(spec=VirusTotalProvider)
    release = threading.Event()

    async def delayed_lookup(_sha256: str):
        if not await asyncio.to_thread(release.wait, 5):
            raise TimeoutError("test provider release timed out")
        return REPORT

    provider.lookup_hash.side_effect = delayed_lookup
    service = ThreatIntelligenceService(
        settings_store=settings,
        provider=provider,
        cache=VirusTotalCache(tmp_path / "vt.db"),
    )
    result = ScanResult(target="/sample", clean=True, metadata={"sha256": SHA256})

    first = asyncio.create_task(service.lookup_scan_result(result))
    second = asyncio.create_task(service.lookup_scan_result(result))
    await asyncio.sleep(0)
    release.set()
    assert await asyncio.gather(first, second) == [REPORT, REPORT]
    provider.lookup_hash.assert_awaited_once_with(SHA256)
    service.close()


@pytest.mark.asyncio
async def test_service_retries_transient_lookup_failures(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        service_module, "VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED", True
    )
    monkeypatch.setattr(service_module.asyncio, "sleep", AsyncMock())
    settings = SettingsStore(tmp_path / "settings.json")
    settings.save(AppSettings(intelligence_enabled=True, intelligence_profile="public"))
    provider = AsyncMock(spec=VirusTotalProvider)
    provider.lookup_hash.side_effect = [
        VirusTotalTransientError("temporary"),
        VirusTotalTransientError("temporary"),
        REPORT,
    ]
    service = ThreatIntelligenceService(
        settings_store=settings,
        provider=provider,
        cache=VirusTotalCache(tmp_path / "vt.db"),
    )
    result = ScanResult(target="/sample", clean=True, metadata={"sha256": SHA256})

    assert await service.lookup_scan_result(result) == REPORT
    assert provider.lookup_hash.await_count == 3
    service.close()


@pytest.mark.asyncio
async def test_cancelling_waiter_does_not_cancel_shared_lookup(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        service_module, "VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED", True
    )
    settings = SettingsStore(tmp_path / "settings.json")
    settings.save(AppSettings(intelligence_enabled=True, intelligence_profile="public"))
    provider = AsyncMock(spec=VirusTotalProvider)
    entered = threading.Event()
    release = threading.Event()

    async def delayed_lookup(_sha256: str):
        entered.set()
        if not await asyncio.to_thread(release.wait, 5):
            raise TimeoutError("test provider release timed out")
        return REPORT

    provider.lookup_hash.side_effect = delayed_lookup
    service = ThreatIntelligenceService(
        settings_store=settings,
        provider=provider,
        cache=VirusTotalCache(tmp_path / "vt.db"),
    )
    result = ScanResult(target="/sample", clean=True, metadata={"sha256": SHA256})

    leader = asyncio.create_task(service.lookup_scan_result(result))
    assert await asyncio.to_thread(entered.wait, 2)
    waiter = asyncio.create_task(service.lookup_scan_result(result))
    await asyncio.sleep(0)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter

    release.set()
    assert await leader == REPORT
    provider.lookup_hash.assert_awaited_once_with(SHA256)
    service.close()


@pytest.mark.asyncio
async def test_valid_cached_report_is_reused_without_secret_store_access(
    tmp_path, monkeypatch
) -> None:
    from unittest.mock import Mock

    monkeypatch.setattr(
        service_module, "VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED", True
    )
    settings = SettingsStore(tmp_path / "settings.json")
    settings.save(AppSettings(intelligence_enabled=True, intelligence_profile="premium"))
    secret_store = Mock()
    secret_store.get_credential.side_effect = AssertionError(
        "a cache hit must not access Secret Service"
    )
    cache = VirusTotalCache(tmp_path / "vt.db")
    cache.put(SHA256, "premium", REPORT)
    service = ThreatIntelligenceService(
        settings_store=settings,
        secret_store=secret_store,
        cache=cache,
    )
    result = ScanResult(target="/sample", clean=True, metadata={"sha256": SHA256})

    assert await service.lookup_scan_result(result) == REPORT
    secret_store.get_credential.assert_not_called()


@pytest.mark.asyncio
async def test_service_honors_retry_after_for_rate_limited_lookup(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(
        service_module, "VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED", True
    )
    sleep = AsyncMock()
    monkeypatch.setattr(service_module.asyncio, "sleep", sleep)
    settings = SettingsStore(tmp_path / "settings.json")
    settings.save(AppSettings(intelligence_enabled=True, intelligence_profile="premium"))
    provider = AsyncMock(spec=VirusTotalProvider)
    provider.lookup_hash.side_effect = [
        VirusTotalAPIError(429, "rate limited", retry_after=3),
        REPORT,
    ]
    service = ThreatIntelligenceService(
        settings_store=settings,
        provider=provider,
        cache=VirusTotalCache(tmp_path / "vt.db"),
    )
    result = ScanResult(target="/sample", clean=True, metadata={"sha256": SHA256})

    assert await service.lookup_scan_result(result) == REPORT
    provider.lookup_hash.assert_awaited_with(SHA256)
    assert provider.lookup_hash.await_count == 2
    sleep.assert_awaited_once_with(3.0)
    service.close()


@pytest.mark.asyncio
async def test_cache_initialization_failure_is_best_effort(tmp_path, monkeypatch) -> None:
    def fail_cache(*_args, **_kwargs):
        raise OSError("cache directory unavailable")

    monkeypatch.setattr(service_module, "VirusTotalCache", fail_cache)
    settings = SettingsStore(tmp_path / "settings.json")

    service = ThreatIntelligenceService(settings_store=settings)

    assert service.cache is None


@pytest.mark.asyncio
async def test_mutating_returned_upload_lookup_cannot_authorize_upload(
    tmp_path, monkeypatch
) -> None:
    from unittest.mock import Mock

    settings = SettingsStore(tmp_path / "settings.json")
    settings.save(AppSettings(intelligence_enabled=True, intelligence_profile="premium"))
    provider = Mock()
    provider.name = "virustotal"
    provider.lookup_hash = AsyncMock(return_value={
        "provider": "virustotal", "found": True, "sha256": SHA256
    })
    provider.upload_file = AsyncMock()
    service = ThreatIntelligenceService(
        settings_store=settings,
        provider=provider,
        cache=VirusTotalCache(tmp_path / "vt.db"),
    )
    sample = tmp_path / "candidate.bin"
    sample.write_bytes(b"candidate")
    preview = service.preview_file_upload(sample)

    returned = await service.lookup_upload_candidate(preview)
    returned["found"] = False

    with pytest.raises(PermissionError, match="recent successful hash lookup"):
        await service.upload_file(preview, consent=True, lookup_report=returned)
    provider.upload_file.assert_not_awaited()


@pytest.mark.asyncio
async def test_retry_after_above_budget_is_not_shortened_or_retried(
    tmp_path, monkeypatch
) -> None:
    sleep = AsyncMock()
    monkeypatch.setattr(service_module.asyncio, "sleep", sleep)
    settings = SettingsStore(tmp_path / "settings.json")
    settings.save(AppSettings(intelligence_enabled=True, intelligence_profile="premium"))
    provider = AsyncMock(spec=VirusTotalProvider)
    provider.lookup_hash.side_effect = VirusTotalAPIError(
        429, "rate limited", retry_after=999
    )
    service = ThreatIntelligenceService(
        settings_store=settings,
        provider=provider,
        cache=VirusTotalCache(tmp_path / "vt.db"),
    )
    result = ScanResult(target="/sample", clean=True, metadata={"sha256": SHA256})

    report = await service.lookup_scan_result(result)

    assert report is not None
    assert report["error"] == "VirusTotal lookup failed"
    provider.lookup_hash.assert_awaited_once_with(SHA256)
    sleep.assert_not_awaited()
    service.close()


@pytest.mark.asyncio
async def test_cancelling_leader_does_not_cancel_shared_lookup(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        service_module, "VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED", True
    )
    settings = SettingsStore(tmp_path / "settings.json")
    settings.save(AppSettings(intelligence_enabled=True, intelligence_profile="public"))
    provider = AsyncMock(spec=VirusTotalProvider)
    entered = threading.Event()
    release = threading.Event()

    async def delayed_lookup(_sha256: str):
        entered.set()
        if not await asyncio.to_thread(release.wait, 5):
            raise TimeoutError("test provider release timed out")
        return REPORT

    provider.lookup_hash.side_effect = delayed_lookup
    service = ThreatIntelligenceService(
        settings_store=settings, provider=provider,
        cache=VirusTotalCache(tmp_path / "vt.db"),
    )
    result = ScanResult(target="/sample", clean=True, metadata={"sha256": SHA256})

    leader = asyncio.create_task(service.lookup_scan_result(result))
    assert await asyncio.to_thread(entered.wait, 2)
    waiter = asyncio.create_task(service.lookup_scan_result(result))
    await asyncio.sleep(0)
    leader.cancel()
    with pytest.raises(asyncio.CancelledError):
        await leader

    release.set()
    assert await waiter == REPORT
    assert not service._inflight
    assert not service._lookup_tasks
    provider.lookup_hash.assert_awaited_once_with(SHA256)
    service.close()


def test_cache_v1_migrates_and_keeps_profile_entries_independent(tmp_path) -> None:
    path = tmp_path / "legacy-vt.db"
    acquired = 1000.0
    report_public = {**REPORT, "profile_marker": "public"}
    report_premium = {**REPORT, "profile_marker": "premium"}
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE vt_hash_cache (
                sha256 TEXT PRIMARY KEY,
                profile TEXT NOT NULL CHECK(profile IN ('public', 'premium')),
                acquired_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                report_json TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "INSERT INTO vt_hash_cache VALUES (?, ?, ?, ?, ?)",
            (SHA256, "public", acquired, acquired + 5000,
             __import__("json").dumps(report_public)),
        )
        connection.execute("PRAGMA user_version = 1")

    cache = VirusTotalCache(path, clock=lambda: acquired + 10)
    assert cache.get(SHA256, "public") == report_public
    assert cache.get(SHA256, "premium") is None
    cache.put(SHA256, "premium", report_premium)
    assert cache.get(SHA256, "public") == report_public
    assert cache.get(SHA256, "premium") == report_premium
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert connection.execute(
            "SELECT COUNT(*) FROM vt_hash_cache WHERE sha256 = ?", (SHA256,)
        ).fetchone()[0] == 2


def test_service_deduplicates_across_event_loops_when_leader_loop_closes(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(
        service_module, "VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED", True
    )
    settings = SettingsStore(tmp_path / "settings.json")
    settings.save(AppSettings(intelligence_enabled=True, intelligence_profile="public"))
    provider = AsyncMock(spec=VirusTotalProvider)
    provider_started = threading.Event()
    release_provider = threading.Event()

    async def delayed_lookup(_sha256: str):
        provider_started.set()
        if not await asyncio.to_thread(release_provider.wait, 5):
            raise TimeoutError("test provider release timed out")
        return REPORT

    provider.lookup_hash.side_effect = delayed_lookup
    service = ThreatIntelligenceService(
        settings_store=settings, provider=provider,
        cache=VirusTotalCache(tmp_path / "vt.db"),
    )
    result = ScanResult(target="/sample", clean=True, metadata={"sha256": SHA256})
    waiter_entered = threading.Event()

    def run_leader():
        async def call():
            leader = asyncio.create_task(service.lookup_scan_result(result))
            if not await asyncio.to_thread(provider_started.wait, 2):
                raise AssertionError("provider lookup did not start")
            leader.cancel()
            with pytest.raises(asyncio.CancelledError):
                await leader
            return "leader loop closed"
        return asyncio.run(call())

    def run_waiter():
        async def call():
            waiter_entered.set()
            return await service.lookup_scan_result(result)
        return asyncio.run(call())

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            leader_future = pool.submit(run_leader)
            assert provider_started.wait(2)
            waiter_future = pool.submit(run_waiter)
            assert waiter_entered.wait(2)
            time.sleep(0.1)
            # asyncio.run() has returned: the leader's caller loop is now closed.
            assert leader_future.result(timeout=5) == "leader loop closed"
            release_provider.set()
            assert waiter_future.result(timeout=5) == REPORT

        provider.lookup_hash.assert_awaited_once_with(SHA256)
        assert not service._inflight
        assert not service._lookup_tasks
    finally:
        release_provider.set()
        service.close()


def test_service_owned_loop_signals_ready_only_after_running() -> None:
    worker = service_module._ServiceOwnedEventLoop()
    ready_states: list[bool] = []
    original_ready = worker._ready

    class ObservedReady:
        def wait(self, timeout=None):
            return original_ready.wait(timeout)

        def set(self):
            loop = worker._loop
            ready_states.append(bool(loop and loop.is_running()))
            original_ready.set()

    worker._ready = ObservedReady()  # type: ignore[assignment]
    try:
        future = worker.submit(asyncio.sleep(0, result="ready"))
        assert future.result(timeout=2) == "ready"
        assert ready_states == [True]
    finally:
        worker.close()


def test_service_owned_loop_close_during_startup_stops_worker(monkeypatch) -> None:
    entered_run_forever = threading.Event()
    allow_run_forever = threading.Event()
    stop_queued = threading.Event()

    class GatedEventLoop(asyncio.SelectorEventLoop):
        def run_forever(self) -> None:
            entered_run_forever.set()
            if not allow_run_forever.wait(2):
                raise TimeoutError("test did not release event-loop startup")
            super().run_forever()

        def call_soon_threadsafe(self, callback, *args, **kwargs):
            if callback == self.stop:
                stop_queued.set()
            return super().call_soon_threadsafe(callback, *args, **kwargs)

    monkeypatch.setattr(
        service_module.asyncio, "new_event_loop", GatedEventLoop
    )
    worker = service_module._ServiceOwnedEventLoop()
    submit_errors: list[BaseException] = []

    def submit() -> None:
        try:
            worker.submit(asyncio.sleep(0))
        except BaseException as exc:
            submit_errors.append(exc)

    submitter = threading.Thread(target=submit)
    submitter.start()
    assert entered_run_forever.wait(2)

    closer = threading.Thread(target=worker.close, kwargs={"timeout": 2})
    closer.start()
    try:
        assert stop_queued.wait(2)
    finally:
        allow_run_forever.set()

    submitter.join(timeout=2)
    closer.join(timeout=2)
    assert not submitter.is_alive()
    assert not closer.is_alive()
    assert worker._thread is not None and not worker._thread.is_alive()
    assert submit_errors and isinstance(submit_errors[0], RuntimeError)



def test_provider_rate_lock_serializes_calls_from_distinct_event_loops(tmp_path) -> None:
    provider = VirusTotalProvider(
        "test-key",
        profile="premium",
        min_request_interval=0,
        rate_limit_path=tmp_path / "quota.json",
    )
    entered = threading.Event()
    release = threading.Event()
    state_lock = threading.Lock()
    active = 0
    maximum_active = 0

    def reserve() -> float:
        nonlocal active, maximum_active
        with state_lock:
            active += 1
            maximum_active = max(maximum_active, active)
            first = active == 1
        if first:
            entered.set()
            assert release.wait(2)
        with state_lock:
            active -= 1
        return 0.0

    provider._limiter.reserve = reserve

    def run_reservation() -> None:
        asyncio.run(provider._reserve())

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(run_reservation)
        assert entered.wait(2)
        second = pool.submit(run_reservation)
        time.sleep(0.05)
        release.set()
        first.result(timeout=3)
        second.result(timeout=3)

    assert maximum_active == 1


def test_rate_limiter_lock_wait_is_bounded(tmp_path) -> None:
    path = tmp_path / "quota.json"
    limiter = PersistentRateLimiter(
        "premium", state_path=path, min_interval=0, lock_timeout=0.1
    )
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError, match="quota state lock"):
            limiter.reserve()
        assert time.monotonic() - started < 1.0
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def test_service_worker_shutdown_drains_bounded_limiter_executor(tmp_path) -> None:
    limiter = PersistentRateLimiter(
        "premium",
        state_path=tmp_path / "quota.json",
        min_interval=0,
        lock_timeout=0.15,
    )
    fd = os.open(limiter.path, os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    worker = service_module._ServiceOwnedEventLoop()
    started = threading.Event()

    async def reserve_while_locked() -> float:
        started.set()
        return await asyncio.to_thread(limiter.reserve)

    try:
        future = worker.submit(reserve_while_locked())
        assert started.wait(2)
        worker.close(timeout=2)
        assert worker._thread is not None and not worker._thread.is_alive()
        assert future.done()
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)



def test_provider_rate_reservation_does_not_create_default_executor(tmp_path) -> None:
    provider = VirusTotalProvider(
        "test-key",
        profile="premium",
        min_request_interval=0,
        rate_limit_path=tmp_path / "quota.json",
    )
    provider._limiter.reserve = lambda: 0.0

    async def reserve() -> None:
        await provider._reserve()
        assert asyncio.get_running_loop()._default_executor is None

    asyncio.run(reserve())


def test_bounded_dns_resolver_uses_daemon_thread_without_executor(monkeypatch) -> None:
    started = threading.Event()
    release = threading.Event()

    def blocked_getaddrinfo(host, port, *, family, type):
        started.set()
        if not release.wait(2):
            raise TimeoutError("test DNS release timed out")
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))
        ]

    monkeypatch.setattr(virustotal_module.socket, "getaddrinfo", blocked_getaddrinfo)
    resolver = virustotal_module._BoundedDaemonResolver(timeout=1)

    async def resolve() -> None:
        task = asyncio.create_task(resolver.resolve("example.invalid", 443))
        while not started.is_set():
            await asyncio.sleep(0.001)
        assert asyncio.get_running_loop()._default_executor is None
        release.set()
        records = await task
        assert records[0]["host"] == "127.0.0.1"
        assert records[0]["port"] == 443

    async def run() -> None:
        try:
            await resolve()
        finally:
            release.set()
            await resolver.close()

    asyncio.run(run())


def test_worker_shutdown_does_not_wait_for_blocked_dns_thread(monkeypatch) -> None:
    started = threading.Event()
    release = threading.Event()

    def blocked_getaddrinfo(host, port, *, family, type):
        started.set()
        release.wait(3)
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))
        ]

    monkeypatch.setattr(virustotal_module.socket, "getaddrinfo", blocked_getaddrinfo)
    resolver = virustotal_module._BoundedDaemonResolver(timeout=10)
    worker = service_module._ServiceOwnedEventLoop()

    async def resolve() -> None:
        await resolver.resolve("example.invalid", 443)

    try:
        future = worker.submit(resolve())
        assert started.wait(2)
        worker.close(timeout=1)
        assert worker._thread is not None and not worker._thread.is_alive()
        assert worker._loop is not None
        assert worker._loop._default_executor is None
        assert future.done()
    finally:
        release.set()
        asyncio.run(resolver.close())
        worker.close(timeout=1)
