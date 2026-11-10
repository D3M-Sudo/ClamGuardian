"""Persistent VirusTotal cache and shared lookup-service regression tests."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest

from clamguardian.core.base import ScanResult
from clamguardian.core.settings import AppSettings, SettingsStore
from clamguardian.intelligence import service as service_module
from clamguardian.intelligence.cache import VirusTotalCache
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


@pytest.mark.asyncio
async def test_service_deduplicates_concurrent_lookups(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        service_module, "VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED", True
    )
    settings = SettingsStore(tmp_path / "settings.json")
    settings.save(AppSettings(intelligence_enabled=True, intelligence_profile="public"))
    provider = AsyncMock(spec=VirusTotalProvider)
    release = asyncio.Event()

    async def delayed_lookup(_sha256: str):
        await release.wait()
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


@pytest.mark.asyncio
async def test_cancelling_waiter_does_not_cancel_shared_lookup(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        service_module, "VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED", True
    )
    settings = SettingsStore(tmp_path / "settings.json")
    settings.save(AppSettings(intelligence_enabled=True, intelligence_profile="public"))
    provider = AsyncMock(spec=VirusTotalProvider)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def delayed_lookup(_sha256: str):
        entered.set()
        await release.wait()
        return REPORT

    provider.lookup_hash.side_effect = delayed_lookup
    service = ThreatIntelligenceService(
        settings_store=settings,
        provider=provider,
        cache=VirusTotalCache(tmp_path / "vt.db"),
    )
    result = ScanResult(target="/sample", clean=True, metadata={"sha256": SHA256})

    leader = asyncio.create_task(service.lookup_scan_result(result))
    await entered.wait()
    waiter = asyncio.create_task(service.lookup_scan_result(result))
    await asyncio.sleep(0)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter

    release.set()
    assert await leader == REPORT
    provider.lookup_hash.assert_awaited_once_with(SHA256)


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