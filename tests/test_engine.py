"""Unit tests for the ClamAV engine without requiring ClamAV on the test host."""

from pathlib import Path

import pytest

from clamguardian.engines.clamav import ClamAVEngine


@pytest.mark.asyncio
async def test_cli_fallback_scans_and_normalizes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "sample.txt"
    target.write_text("clean")
    engine = ClamAVEngine(socket_path=tmp_path / "missing.sock")

    async def fake_command(args):
        assert args == ["clamscan", "--no-summary", str(target)]
        return f"{target}: OK\n", 0

    monkeypatch.setattr(engine, "_run_command", fake_command)
    result = await engine.scan(target, recursive=True)
    assert result.clean is True
    assert result.threats == ()
    assert result.engine == "clamscan"


@pytest.mark.asyncio
async def test_threat_output_is_detected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "eicar.com"
    target.write_text("test")
    engine = ClamAVEngine(socket_path=tmp_path / "missing.sock")

    async def fake_command(args):
        return f"{target}: Eicar-Test-Signature FOUND\n", 1

    monkeypatch.setattr(engine, "_run_command", fake_command)
    result = await engine.scan(target)
    assert result.clean is False
    assert result.threats == (f"{target}: Eicar-Test-Signature FOUND",)
