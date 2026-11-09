"""Tests for dynamic threat intelligence integration (VirusTotal & Provider Manager)."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from clamguardian.core.base import ScanResult, ScanStatus
from clamguardian.core.settings import AppSettings, SettingsStore
from clamguardian.intelligence import service as intelligence_service_module
from clamguardian.intelligence.manager import ThreatProviderManager
from clamguardian.intelligence.secrets import IntelligenceSecretStore, SecretStorageError
from clamguardian.intelligence.service import ThreatIntelligenceService
from clamguardian.intelligence.virustotal import VirusTotalProvider


def test_virustotal_provider_key_validation() -> None:
    with pytest.raises(ValueError, match="API key is required"):
        VirusTotalProvider("")


def test_virustotal_invalid_hash_rejection() -> None:
    provider = VirusTotalProvider("fake_api_key")

    with pytest.raises(ValueError, match="64-character hexadecimal digest"):
        asyncio.run(provider.lookup_hash("invalid_hash"))


def test_virustotal_has_no_file_upload_methods() -> None:
    """Guarantee VirusTotal provider only performs hash lookups and never uploads files."""
    provider = VirusTotalProvider("fake_key")
    assert hasattr(provider, "lookup_hash")
    assert not hasattr(provider, "upload_file")
    assert not hasattr(provider, "submit_file")


def test_threat_provider_manager_registration() -> None:
    provider = VirusTotalProvider("test_key")
    manager = ThreatProviderManager()
    manager.register(provider)

    assert "virustotal" in manager.names()
    assert manager.get("virustotal") is provider


def test_secret_store_fail_closed_without_libsecret() -> None:
    store = IntelligenceSecretStore()
    if not store.is_available():
        with pytest.raises(SecretStorageError, match="Secure credential storage"):
            store.get_api_key()
        with pytest.raises(SecretStorageError, match="Secure credential storage"):
            store.set_api_key("some_key")


@pytest.mark.asyncio
async def test_intelligence_service_zero_network_when_disabled(tmp_path) -> None:
    settings_file = tmp_path / "settings.json"
    settings_store = SettingsStore(settings_file)
    settings_store.save(AppSettings(intelligence_enabled=False))

    mock_provider = AsyncMock(spec=VirusTotalProvider)
    service = ThreatIntelligenceService(
        settings_store=settings_store,
        provider=mock_provider,
    )

    result = ScanResult(
        target="/tmp/test.txt",
        clean=True,
        metadata={"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    )
    verdict = await service.lookup_scan_result(result)
    assert verdict is None
    assert mock_provider.lookup_hash.call_count == 0


@pytest.mark.asyncio
async def test_intelligence_service_lookup_when_enabled(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        intelligence_service_module, "VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED", True
    )
    settings_file = tmp_path / "settings.json"
    settings_store = SettingsStore(settings_file)
    settings_store.save(AppSettings(intelligence_enabled=True))

    mock_provider = AsyncMock(spec=VirusTotalProvider)
    mock_provider.name = "virustotal"
    mock_provider.lookup_hash.return_value = {
        "provider": "virustotal",
        "found": True,
        "malicious": True,
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }

    service = ThreatIntelligenceService(
        settings_store=settings_store,
        provider=mock_provider,
    )

    result = ScanResult(
        target="/tmp/test.txt",
        clean=True,
        metadata={"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    )
    verdict = await service.lookup_scan_result(result)
    assert verdict is not None
    assert verdict["found"] is True
    assert verdict["malicious"] is True
    assert result.clean is True
    assert result.status is ScanStatus.CLEAN


@pytest.mark.asyncio
async def test_intelligence_service_reuses_provider_and_enforces_terms_gate(
    tmp_path, monkeypatch
) -> None:
    store = SettingsStore(tmp_path / "settings.json")
    store.save(AppSettings(intelligence_enabled=True))
    provider = AsyncMock(spec=VirusTotalProvider)
    service = ThreatIntelligenceService(settings_store=store, provider=provider)

    monkeypatch.setattr(
        intelligence_service_module, "VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED", False
    )
    result = ScanResult(target="/tmp/file", clean=True, metadata={"sha256": "a" * 64})
    assert await service.lookup_scan_result(result) is None
    provider.lookup_hash.assert_not_awaited()

    monkeypatch.setattr(
        intelligence_service_module, "VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED", True
    )
    service._provider = provider
    service._provider_initialized = True
    assert service.get_provider() is provider
    assert service.get_provider() is provider


@pytest.mark.asyncio
async def test_virustotal_rate_limiting() -> None:
    provider = VirusTotalProvider("fake_key", min_request_interval=0.05)

    with patch("aiohttp.ClientSession.get") as mock_get:
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(
            return_value={"data": {"attributes": {"last_analysis_stats": {}}}}
        )
        mock_get.return_value.__aenter__.return_value = mock_resp

        start = asyncio.get_running_loop().time()
        test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        await provider.lookup_hash(test_hash)
        await provider.lookup_hash(test_hash)
        elapsed = asyncio.get_running_loop().time() - start

        assert elapsed >= 0.04
