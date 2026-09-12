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
        assert args == [
            "clamscan",
            "--no-summary",
            "--recursive",
            "--scan-archive=yes",
            "--scan-mail=yes",
            str(target),
        ]
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


@pytest.mark.asyncio
async def test_engine_single_file_sha256_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import hashlib

    file_target = tmp_path / "sample.txt"
    file_target.write_text("content for hash test")
    expected_hash = hashlib.sha256(b"content for hash test").hexdigest()

    dir_target = tmp_path / "mydir"
    dir_target.mkdir()

    engine = ClamAVEngine(socket_path=tmp_path / "missing.sock")

    async def fake_command(args):
        return "OK\n", 0

    monkeypatch.setattr(engine, "_run_command", fake_command)

    file_result = await engine.scan(file_target)
    assert file_result.sha256 == expected_hash

    dir_result = await engine.scan(dir_target)
    assert dir_result.sha256 is None


@pytest.mark.asyncio
async def test_engine_flatpak_host_command_construction(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "file.txt"
    target.write_text("hello")
    engine = ClamAVEngine(socket_path=tmp_path / "missing.sock", flatpak_host=True)

    captured_command: list[str] = []

    async def fake_command(args):
        # We intercept _run_command or test flatpak_host in _run_command directly
        return "OK\n", 0

    # Let's test _run_command directly to check command construction
    async def fake_exec(*cmd, **kwargs):
        captured_command.extend(cmd)
        class FakeProcess:
            returncode = 0
            async def communicate(self):
                return b"OK\n", b""
        return FakeProcess()

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
    out, code = await engine._run_command(["clamscan", "--version"])
    assert code == 0
    assert captured_command[:2] == ["flatpak-spawn", "--host"]
    assert captured_command[2:] == ["clamscan", "--version"]


@pytest.mark.asyncio
async def test_special_filesystem_objects_handling(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import os

    from clamguardian.core.base import compute_file_sha256

    # 1. Symlink to regular file
    real_file = tmp_path / "real.txt"
    real_file.write_text("hello symlink")
    symlink = tmp_path / "link.txt"
    symlink.symlink_to(real_file)

    assert compute_file_sha256(symlink) is not None

    # 2. Broken symlink
    broken_symlink = tmp_path / "broken_link.txt"
    broken_symlink.symlink_to(tmp_path / "nonexistent.txt")

    assert compute_file_sha256(broken_symlink) is None
    with pytest.raises(FileNotFoundError):
        # Engine resolve(strict=True) raises FileNotFoundError for broken symlinks
        engine = ClamAVEngine(socket_path=tmp_path / "missing.sock")
        await engine.scan(broken_symlink)

    # 3. FIFO / Named Pipe
    fifo_path = tmp_path / "test.fifo"
    try:
        os.mkfifo(fifo_path)
        # compute_file_sha256 MUST NOT block/hang on a FIFO open
        assert compute_file_sha256(fifo_path) is None
    except OSError:
        pass  # mkfifo might fail on unsupported filesystems
