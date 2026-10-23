"""Unit tests for the ClamAV engine without requiring ClamAV on the test host."""

import asyncio
from pathlib import Path

import pytest

from clamguardian.core.base import ScanStatus
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


@pytest.mark.asyncio
async def test_clamd_branch_records_single_file_sha256(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """M4 Final: the preferred clamd path must record the content hash too.

    The digest used to be computed only on the clamscan fallback, so on a host
    with a running clamd no single-file scan ever carried ``metadata["sha256"]``
    and the Threat Intelligence seam had no hash to look up.
    """
    import hashlib

    file_target = tmp_path / "sample.txt"
    file_target.write_text("clamd hash")
    expected_hash = hashlib.sha256(b"clamd hash").hexdigest()

    socket_path = tmp_path / "clamd.ctl"
    socket_path.touch()  # only ``exists()`` gates the socket branch
    engine = ClamAVEngine(socket_path=socket_path)

    async def fake_socket(target, profile):
        return f"{target}: OK\n", 0, ()

    monkeypatch.setattr(engine, "_scan_socket", fake_socket)

    result = await engine.scan(file_target)
    assert result.engine == "clamd"
    assert result.sha256 == expected_hash
    assert result.metadata["profile_id"] == "default"


@pytest.mark.asyncio
async def test_clamd_branch_has_no_sha256_for_directories(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A directory scan served by clamd must not record a misleading digest."""
    dir_target = tmp_path / "scanned_dir"
    dir_target.mkdir()

    socket_path = tmp_path / "clamd.ctl"
    socket_path.touch()
    engine = ClamAVEngine(socket_path=socket_path)

    async def fake_socket(target, profile):
        return f"{target}: OK\n", 0, ()

    monkeypatch.setattr(engine, "_scan_socket", fake_socket)

    result = await engine.scan(dir_target)
    assert result.engine == "clamd"
    assert result.sha256 is None


@pytest.mark.asyncio
async def test_timed_out_scan_still_records_applied_profile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A timed-out scan must still state which profile was applied.

    No digest is computed in this case: the engine already gave up on the
    target, and hashing it afterwards would repeat the very work that timed out.
    """
    target = tmp_path / "slow.bin"
    target.write_text("payload")
    engine = ClamAVEngine(socket_path=tmp_path / "missing.sock")

    async def fake_cli(target, *, profile):
        raise TimeoutError

    monkeypatch.setattr(engine, "_run_cli_scan", fake_cli)

    result = await engine.scan(target)
    assert result.status is ScanStatus.TIMEOUT
    assert result.metadata["profile_id"] == "default"
    assert result.sha256 is None


@pytest.mark.asyncio
async def test_special_targets_are_rejected_before_scanning(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """M5: FIFOs and sockets must be refused explicitly, never handed to ClamAV.

    Reading a FIFO blocks until a writer appears, and a device node may be
    unbounded: the engine has to reject these targets *before* invoking any
    backend, as required by the M5 "explicit scan target validation" scope.
    """
    import os
    import socket

    engine = ClamAVEngine(socket_path=tmp_path / "missing.sock")
    invoked: list[list[str]] = []

    async def fake_command(args):
        invoked.append(list(args))
        return "OK\n", 0

    monkeypatch.setattr(engine, "_run_command", fake_command)

    fifo = tmp_path / "pipe.fifo"
    try:
        os.mkfifo(fifo)
    except OSError:  # pragma: no cover - filesystem without FIFO support
        pytest.skip("mkfifo is not supported on this filesystem")

    fifo_result = await engine.scan(fifo)
    assert fifo_result.status is ScanStatus.ERROR
    assert "not a regular file or directory" in (fifo_result.error or "")

    socket_path = tmp_path / "agent.sock"
    unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        unix_socket.bind(str(socket_path))
        socket_result = await engine.scan(socket_path)
    finally:
        unix_socket.close()

    assert socket_result.status is ScanStatus.ERROR
    assert "not a regular file or directory" in (socket_result.error or "")
    assert invoked == [], "no backend may be invoked for a special target"


@pytest.mark.asyncio
async def test_clean_path_containing_found_is_not_a_detection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A clean path containing the literal " FOUND" must not be reported as a threat."""
    target = tmp_path / "my FOUND report.txt"
    target.write_text("clean")
    engine = ClamAVEngine(socket_path=tmp_path / "missing.sock")

    async def fake_command(args):
        return f"{target}: OK\n", 0

    monkeypatch.setattr(engine, "_run_command", fake_command)

    result = await engine.scan(target)
    assert result.status is ScanStatus.CLEAN
    assert result.threats == ()


async def _serve_clamd(socket_path: Path, lines: list[bytes]):
    """Serve one clamd command, streaming *lines* like the real daemon."""

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readline()
        for line in lines:
            writer.write(line)
            await writer.drain()
            await asyncio.sleep(0)
        writer.close()
        await writer.wait_closed()

    return await asyncio.start_unix_server(handle, path=str(socket_path))


@pytest.mark.asyncio
async def test_clamd_directory_scan_reads_every_result_line(tmp_path: Path) -> None:
    """A directory scan must not stop at the first "OK" line (AUD-01)."""
    target = tmp_path / "scanned"
    target.mkdir()
    socket_path = tmp_path / "clamd.ctl"
    lines = [
        b"clean-a.txt: OK\n",
        b"clean-b.txt: OK\n",
        b"eicar.txt: Eicar-Test-Signature FOUND\n",
        b"\n----------- SCAN SUMMARY -----------\nInfected files: 1\n",
    ]

    server = await _serve_clamd(socket_path, lines)
    async with server:
        engine = ClamAVEngine(socket_path=socket_path, command_timeout=5)
        result = await engine.scan(target)

    assert result.status is ScanStatus.INFECTED
    assert result.threats == ("eicar.txt: Eicar-Test-Signature FOUND",)
    assert result.engine == "clamd"


@pytest.mark.asyncio
async def test_target_with_newline_is_rejected_before_clamd(tmp_path: Path) -> None:
    """Control characters must never reach the line-oriented clamd channel."""
    target = tmp_path / "evil\nSHUTDOWN"
    target.write_text("payload")
    engine = ClamAVEngine(socket_path=tmp_path / "clamd.ctl")

    result = await engine.scan(target)

    assert result.status is ScanStatus.ERROR
    assert "control characters" in (result.error or "")

    from clamguardian.core.profiles import DEFAULT_PROFILE

    with pytest.raises(ValueError, match="control characters"):
        await engine._scan_socket(target, DEFAULT_PROFILE)


@pytest.mark.asyncio
async def test_clamd_response_size_is_bounded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from clamguardian.core.profiles import DEFAULT_PROFILE

    target = tmp_path / "target.txt"
    target.write_text("x")
    socket_path = tmp_path / "clamd.ctl"
    monkeypatch.setattr("clamguardian.engines.clamav.MAX_RESPONSE_BYTES", 32)

    server = await _serve_clamd(socket_path, [b"x" * 64])
    async with server:
        engine = ClamAVEngine(socket_path=socket_path, command_timeout=5)
        with pytest.raises(ValueError, match="size limit"):
            await engine._scan_socket(target, DEFAULT_PROFILE)
