"""Tests for dynamic threat intelligence integration (VirusTotal & Provider Manager)."""

from __future__ import annotations

import asyncio
from io import StringIO
from unittest.mock import AsyncMock, Mock, patch

import pytest

from clamguardian.core.base import ScanResult, ScanStatus
from clamguardian.core.settings import AppSettings, SettingsStore
from clamguardian.intelligence import service as intelligence_service_module
from clamguardian.intelligence.manager import ThreatProviderManager
from clamguardian.intelligence.secrets import IntelligenceSecretStore, SecretStorageError
from clamguardian.intelligence.service import ThreatIntelligenceService
from clamguardian.intelligence import virustotal as virustotal_module
from clamguardian.intelligence.virustotal import VirusTotalProvider


def test_virustotal_provider_key_validation() -> None:
    with pytest.raises(ValueError, match="API key is required"):
        VirusTotalProvider("")


def test_virustotal_invalid_hash_rejection() -> None:
    provider = VirusTotalProvider("fake_api_key")

    with pytest.raises(ValueError, match="64-character hexadecimal digest"):
        asyncio.run(provider.lookup_hash("invalid_hash"))


def test_virustotal_upload_is_available_only_as_explicit_provider_operation() -> None:
    provider = VirusTotalProvider("fake_key")
    assert hasattr(provider, "lookup_hash")
    assert hasattr(provider, "upload_file")
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
    secret_store = Mock()
    secret_store.get_credential.return_value = "test-api-key"
    service = ThreatIntelligenceService(settings_store=store, secret_store=secret_store)

    monkeypatch.setattr(
        intelligence_service_module, "VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED", False
    )
    result = ScanResult(target="/tmp/file", clean=True, metadata={"sha256": "a" * 64})
    assert await service.lookup_scan_result(result) is None
    provider.lookup_hash.assert_not_awaited()
    secret_store.get_credential.assert_not_called()

    monkeypatch.setattr(
        intelligence_service_module, "VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED", True
    )
    monkeypatch.setattr(
        intelligence_service_module, "VirusTotalProvider", lambda _key, profile: provider
    )
    assert service.get_provider() is provider
    assert service.get_provider() is provider
    secret_store.get_credential.assert_called_once_with("public")


def test_virustotal_default_rate_limit_is_at_least_four_per_minute() -> None:
    provider = VirusTotalProvider("fake_key")
    assert provider._min_interval >= 15.0

@pytest.mark.asyncio
async def test_virustotal_rate_limit_is_shared_between_provider_instances(tmp_path) -> None:
    state = tmp_path / "shared-rate-limit"
    first = VirusTotalProvider("first", min_request_interval=0.05, rate_limit_path=state)
    second = VirusTotalProvider("second", min_request_interval=0.05, rate_limit_path=state)

    await first._enforce_rate_limit()
    started = asyncio.get_running_loop().time()
    await second._enforce_rate_limit()
    assert asyncio.get_running_loop().time() - started >= 0.04


@pytest.mark.asyncio
async def test_virustotal_fails_closed_on_corrupt_rate_limit_state(tmp_path) -> None:
    state = tmp_path / "corrupt-rate-limit"
    state.write_text("not-a-timestamp", encoding="ascii")
    provider = VirusTotalProvider("fake", rate_limit_path=state)
    with pytest.raises(RuntimeError, match="quota state is corrupt"):
        await provider._enforce_rate_limit()


def test_cli_lookup_requires_opt_in_before_secret_access(tmp_path, monkeypatch) -> None:
    from clamguardian.cli.main import run

    store = SettingsStore(tmp_path / "settings.json")
    store.save(AppSettings(intelligence_enabled=False))
    monkeypatch.setattr("clamguardian.core.settings.SettingsStore", lambda: store)

    def forbidden_secret_store():
        raise AssertionError("Secret Service must not be touched while disabled")

    monkeypatch.setattr(
        "clamguardian.intelligence.secrets.IntelligenceSecretStore",
        forbidden_secret_store,
    )
    output, errors = StringIO(), StringIO()
    code = run(["intel", "lookup", "a" * 64], out=output, err=errors)
    assert code == 2
    assert "disabled" in errors.getvalue()


def test_cli_lookup_respects_maintainer_terms_gate(tmp_path, monkeypatch) -> None:
    from clamguardian.cli.main import run

    store = SettingsStore(tmp_path / "settings.json")
    store.save(AppSettings(intelligence_enabled=True))
    monkeypatch.setattr("clamguardian.core.settings.SettingsStore", lambda: store)
    monkeypatch.setattr(
        "clamguardian.intelligence.virustotal.VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED",
        False,
    )
    output, errors = StringIO(), StringIO()
    code = run(["intel", "lookup", "a" * 64], out=output, err=errors)
    assert code == 3
    assert "eligibility" in errors.getvalue()


def test_cli_set_key_uses_hidden_input_and_secret_service(monkeypatch) -> None:
    import getpass

    from clamguardian.cli.main import run

    class FakeSecretStore:
        stored: str | None = None

        profile: str | None = None

        def set_credential(self, profile: str, value: str) -> None:
            self.profile = profile
            self.stored = value

    fake = FakeSecretStore()
    monkeypatch.setattr(getpass, "getpass", lambda _prompt: "never-echo-this")
    monkeypatch.setattr(
        "clamguardian.intelligence.secrets.IntelligenceSecretStore", lambda: fake
    )
    output, errors = StringIO(), StringIO()
    code = run(["intel", "set-key"], out=output, err=errors)
    assert code == 0
    assert fake.stored == "never-echo-this"
    assert fake.profile == "public"
    assert "never-echo-this" not in output.getvalue()
    assert errors.getvalue() == ""


@pytest.mark.asyncio
async def test_virustotal_rate_limiting(tmp_path) -> None:
    provider = VirusTotalProvider(
        "fake_key",
        min_request_interval=0.05,
        rate_limit_path=tmp_path / "rate-limit",
    )

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



def test_secret_service_availability_checks_dbus_operation(monkeypatch) -> None:
    import sys
    from types import ModuleType, SimpleNamespace

    calls = []
    class FakeSchema:
        @staticmethod
        def new(*_args):
            return object()
    class FakeSecret:
        Schema = FakeSchema
        SchemaFlags = SimpleNamespace(NONE=0)
        SchemaAttributeType = SimpleNamespace(STRING=1)
        @staticmethod
        def password_lookup_sync(*_args):
            calls.append("lookup")
            return None
    fake_repository = ModuleType("gi.repository")
    fake_repository.Secret = FakeSecret
    fake_gi = ModuleType("gi")
    fake_gi.__path__ = []
    fake_gi.require_version = lambda *_args: None
    fake_gi.repository = fake_repository
    monkeypatch.setitem(sys.modules, "gi", fake_gi)
    monkeypatch.setitem(sys.modules, "gi.repository", fake_repository)
    assert IntelligenceSecretStore.is_available() is True
    assert calls == ["lookup"]


def test_settings_persist_explicit_intelligence_profile(tmp_path):
    store = SettingsStore(tmp_path / "settings.json")
    saved = store.save(AppSettings(intelligence_enabled=True, intelligence_profile="premium"))
    assert saved.intelligence_profile == "premium"
    assert store.load().intelligence_profile == "premium"


def test_settings_reject_unknown_intelligence_profile(tmp_path):
    store = SettingsStore(tmp_path / "settings.json")
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text('{"intelligence_profile":"enterprise"}', encoding="utf-8")
    assert store.load().intelligence_profile == "public"


def test_public_profile_daily_quota_is_enforced(tmp_path):
    from clamguardian.intelligence.profiles import APIProfile
    from clamguardian.intelligence.rate_limiter import PersistentRateLimiter, QuotaExceeded
    limiter = PersistentRateLimiter(
        APIProfile.PUBLIC, state_path=tmp_path / "quota.json", min_interval=0,
        public_daily_limit=1,
    )
    assert limiter.reserve() == 0
    with pytest.raises(QuotaExceeded):
        limiter.reserve()


def test_premium_profile_does_not_use_public_daily_quota(tmp_path):
    from clamguardian.intelligence.profiles import APIProfile
    from clamguardian.intelligence.rate_limiter import PersistentRateLimiter

    limiter = PersistentRateLimiter(
        APIProfile.PREMIUM, state_path=tmp_path / "quota.json", min_interval=0,
        public_daily_limit=0,
    )
    assert limiter.reserve() == 0


def test_upload_requires_explicit_per_file_consent(tmp_path):
    from clamguardian.intelligence.upload import preview_upload, submit_after_consent

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"safe test fixture")
    preview = preview_upload(sample)
    provider = Mock()
    with pytest.raises(PermissionError, match="consent"):
        asyncio.run(submit_after_consent(provider, preview, consent=False))
    provider.upload_file.assert_not_called()


def test_public_profile_gate_does_not_implicitly_block_premium(tmp_path, monkeypatch):
    store = SettingsStore(tmp_path / "settings.json")
    store.save(AppSettings(intelligence_enabled=True, intelligence_profile="premium"))
    provider = AsyncMock(spec=VirusTotalProvider)
    secret_store = Mock()
    secret_store.get_credential.return_value = "premium-test-key"
    monkeypatch.setattr(intelligence_service_module, "VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED", False)
    monkeypatch.setattr(
        intelligence_service_module, "VirusTotalProvider", lambda key, profile: provider
    )
    service = ThreatIntelligenceService(settings_store=store, secret_store=secret_store)
    assert service.get_provider() is provider
    secret_store.get_credential.assert_called_once_with("premium")


def test_public_provider_is_blocked_before_network_without_written_authorization():
    provider = VirusTotalProvider("test-key", profile="public")
    with pytest.raises(PermissionError, match="written eligibility authorization"):
        asyncio.run(provider.lookup_hash("a" * 64))


def test_retry_after_cooldown_is_persisted_across_limiter_instances(tmp_path):
    from clamguardian.intelligence.rate_limiter import PersistentRateLimiter

    state = tmp_path / "retry-after.json"
    first = PersistentRateLimiter("premium", state_path=state, min_interval=0)
    first.defer(2)
    second = PersistentRateLimiter("premium", state_path=state, min_interval=0)
    assert second.reserve() > 1.0



def test_provider_upload_requires_fresh_absent_hash_lookup(monkeypatch, tmp_path):
    provider = VirusTotalProvider("test-key", profile="premium")
    monkeypatch.setattr(
        provider, "lookup_hash", AsyncMock(return_value={"found": True})
    )
    sample = tmp_path / "already-known.bin"
    sample.write_bytes(b"fixture")
    with pytest.raises(PermissionError, match="fresh VirusTotal hash lookup"):
        asyncio.run(provider.upload_file(sample, "0" * 64))
