"""Focused tests for VirusTotal upload transport and URL safety."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from clamguardian.intelligence.virustotal import VirusTotalProvider


class _FakeResponse:
    def __init__(self, status: int, payload: dict[str, Any]) -> None:
        self.status = status
        self.headers: dict[str, str] = {}
        self._payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args: object) -> bool:
        return False

    async def json(self) -> dict[str, Any]:
        return self._payload


class _FakeSession:
    def __init__(self, captured: dict[str, Any]) -> None:
        self.captured = captured

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args: object) -> bool:
        return False

    def post(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.captured["url"] = url
        self.captured["kwargs"] = kwargs
        return _FakeResponse(200, {"data": {"id": "analysis-123"}})


def test_premium_upload_posts_only_after_absent_hash_lookup(tmp_path: Path) -> None:
    from unittest.mock import AsyncMock

    sample = tmp_path / "fixture.bin"
    sample.write_bytes(b"non-sensitive test fixture")
    import hashlib

    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    captured: dict[str, Any] = {}
    provider = VirusTotalProvider(
        "test-premium-key",
        profile="premium",
        min_request_interval=0,
        rate_limit_path=tmp_path / "quota.json",
        session_factory=lambda **_kwargs: _FakeSession(captured),
    )
    provider.lookup_hash = AsyncMock(return_value={"found": False})
    analysis_id = asyncio.run(provider.upload_file(sample, digest, consent=True))

    assert analysis_id == "analysis-123"
    assert captured["url"] == "https://www.virustotal.com/api/v3/files"
    assert captured["kwargs"]["allow_redirects"] is False
    assert captured["kwargs"]["data"] is not None
    provider.lookup_hash.assert_awaited_once_with(digest)


def test_upload_url_rejects_untrusted_hosts() -> None:
    import pytest

    with pytest.raises(RuntimeError, match="unsafe upload URL"):
        VirusTotalProvider._validate_upload_url(
            "https://attacker.example/api/v3/files"
        )


def test_upload_url_rejects_unexpected_paths() -> None:
    import pytest

    with pytest.raises(RuntimeError, match="unsafe upload URL"):
        VirusTotalProvider._validate_upload_url(
            "https://www.virustotal.com/api/v3/files/redirect"
        )
