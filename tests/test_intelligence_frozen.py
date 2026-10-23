"""Guards for the frozen threat-intelligence package (AUD-11).

The package ships in 1.x but must stay unreachable until Phase 11 (`v1.2.0`).
These tests fail if a production module starts importing it, if an entry point
is declared, or if the reserved extra stops being empty.
"""

from __future__ import annotations

import ast
import asyncio
import tomllib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from clamguardian.intelligence import ThreatProviderManager, VirusTotalProvider, virustotal

_PACKAGE_ROOT = Path(__file__).resolve().parents[1]
_ROOT_PACKAGE = _PACKAGE_ROOT / "clamguardian"
_INTELLIGENCE_PREFIXES = (
    "clamguardian.intelligence",
    "..intelligence",
    ".intelligence",
)


def _production_modules() -> list[Path]:
    """Return every shipped module except the frozen package itself."""
    return [
        path
        for path in _ROOT_PACKAGE.rglob("*.py")
        if "intelligence" not in path.relative_to(_ROOT_PACKAGE).parts
    ]


def _imported_names(tree: ast.AST) -> Iterator[str]:
    """Yield every module name referenced by import statements."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom):
            prefix = "." * node.level
            module = node.module or ""
            yield prefix + module
            for alias in node.names:
                if alias.name != "*":
                    separator = "." if module else ""
                    yield f"{prefix}{module}{separator}{alias.name}"


def _is_intelligence(name: str) -> bool:
    return any(name == prefix or name.startswith(f"{prefix}.") for prefix in _INTELLIGENCE_PREFIXES)


def _load_pyproject() -> dict[str, Any]:
    return tomllib.loads((_PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_no_production_module_imports_the_frozen_package() -> None:
    offenders: list[str] = []
    for path in _production_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for name in _imported_names(tree):
            if _is_intelligence(name):
                offenders.append(f"{path.relative_to(_PACKAGE_ROOT)}: import {name}")
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and "clamguardian.intelligence" in node.value
            ):
                offenders.append(f"{path.relative_to(_PACKAGE_ROOT)}: string constant")
    assert offenders == []


def test_no_threat_provider_entry_point_is_declared() -> None:
    entry_points = _load_pyproject()["project"].get("entry-points", {})
    assert "clamguardian.threat_providers" not in entry_points


def test_intelligence_extra_is_reserved_and_empty() -> None:
    extras = _load_pyproject()["project"]["optional-dependencies"]
    assert extras["intelligence"] == []


def test_manager_registers_nothing_by_default() -> None:
    assert ThreatProviderManager().names() == ()


def test_virustotal_rejects_key_or_digest_before_any_network_call() -> None:
    with pytest.raises(ValueError, match="API key"):
        VirusTotalProvider("   ")

    provider = VirusTotalProvider("secret-key")
    with pytest.raises(ValueError, match="sha256"):
        asyncio.run(provider.lookup_hash("not-a-digest"))


class _FakeResponse:
    def __init__(self, status: int, payload: dict[str, Any] | None = None, text: str = "") -> None:
        self.status = status
        self._payload = payload or {}
        self._text = text

    async def __aenter__(self) -> _FakeResponse:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def json(self) -> dict[str, Any]:
        return self._payload

    async def text(self) -> str:
        return self._text


class _FakeSession:
    def __init__(self, response: _FakeResponse, captured: dict[str, Any]) -> None:
        self._response = response
        self._captured = captured

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    def get(self, url: str) -> _FakeResponse:
        self._captured["url"] = url
        return self._response


def _fake_session(monkeypatch: pytest.MonkeyPatch, response: _FakeResponse) -> dict[str, Any]:
    captured: dict[str, Any] = {}

    def factory(*args: object, **kwargs: object) -> _FakeSession:
        captured["headers"] = kwargs.get("headers", {})
        return _FakeSession(response, captured)

    monkeypatch.setattr(virustotal.aiohttp, "ClientSession", factory)
    return captured


def test_virustotal_404_returns_not_found_and_sends_hash_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "a" * 64
    captured = _fake_session(monkeypatch, _FakeResponse(404))

    result = asyncio.run(VirusTotalProvider("secret-key").lookup_hash(digest))

    assert result == {"provider": "virustotal", "found": False, "sha256": digest}
    assert str(captured["url"]).endswith(f"/files/{digest}")
    headers = captured["headers"]
    assert isinstance(headers, dict)
    assert headers["x-apikey"] == "secret-key"


def test_virustotal_error_does_not_echo_the_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_session(monkeypatch, _FakeResponse(500, text="upstream boom"))

    with pytest.raises(RuntimeError) as excinfo:
        asyncio.run(VirusTotalProvider("secret-key").lookup_hash("b" * 64))

    message = str(excinfo.value)
    assert "secret-key" not in message
    assert "upstream boom" in message
