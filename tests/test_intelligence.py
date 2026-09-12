"""Tests for dynamic threat intelligence integration (VirusTotal & Provider Manager)."""

from __future__ import annotations

import pytest

from clamguardian.intelligence.manager import ThreatProviderManager
from clamguardian.intelligence.virustotal import VirusTotalProvider


def test_virustotal_provider_key_validation() -> None:
    with pytest.raises(ValueError, match="API key is required"):
        VirusTotalProvider("")


def test_virustotal_invalid_hash_rejection() -> None:
    provider = VirusTotalProvider("fake_api_key")

    with pytest.raises(ValueError, match="64-character hexadecimal digest"):
        import asyncio

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
