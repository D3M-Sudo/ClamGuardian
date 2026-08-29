"""Hybrid ClamAV engine: clamd UNIX socket first, CLI fallback second."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from ..core.base import BaseAVEngine, ScanResult


class ClamAVEngine(BaseAVEngine):
    """Use clamd over UNIX socket when available, otherwise clamscan/freshclam.

    When ``flatpak_host`` is true, command execution is prefixed with
    ``flatpak-spawn --host`` so a sandboxed application can invoke host ClamAV.
    """

    name = "clamav"

    def __init__(
        self,
        socket_path: Path = Path("/run/clamd.ctl"),
        clamscan_binary: str = "clamscan",
        freshclam_binary: str = "freshclam",
        flatpak_host: bool = False,
        command_timeout: float = 300.0,
    ) -> None:
        self.socket_path = Path(socket_path)
        self.clamscan_binary = clamscan_binary
        self.freshclam_binary = freshclam_binary
        self.flatpak_host = flatpak_host
        self.command_timeout = command_timeout

    async def scan(self, target: Path, *, recursive: bool = True) -> ScanResult:
        """Scan *target*, preferring clamd and falling back to clamscan."""
        target = Path(target).expanduser().resolve(strict=True)
        started = datetime.now(UTC)
        if self.socket_path.exists():
            try:
                output, exit_code = await asyncio.wait_for(
                    self._scan_socket(target), self.command_timeout
                )
                return self._result(target, started, output, exit_code, "clamd")
            except (TimeoutError, OSError, ValueError):
                pass
        output, exit_code = await self._run_cli_scan(target, recursive=recursive)
        return self._result(target, started, output, exit_code, "clamscan")

    async def update_signatures(self) -> str:
        """Run freshclam using the host when Flatpak integration is enabled."""
        output, code = await self._run_command([self.freshclam_binary])
        if code != 0:
            raise RuntimeError(f"freshclam failed with exit code {code}: {output.strip()}")
        return output.strip()

    async def _scan_socket(self, target: Path) -> tuple[str, int]:
        reader, writer = await asyncio.open_unix_connection(str(self.socket_path))
        try:
            writer.write(b"SCAN " + os.fsencode(str(target)) + b"\n")
            await writer.drain()
            chunks: list[bytes] = []
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                if b"\n" in chunk and any(token in chunk for token in (b"FOUND", b"OK", b"ERROR")):
                    break
            output = b"".join(chunks).decode("utf-8", errors="replace")
            code = (
                1
                if any(" ERROR" in line or line.endswith("ERROR") for line in output.splitlines())
                else 0
            )
            return output, code
        finally:
            writer.close()
            await writer.wait_closed()

    async def _run_cli_scan(self, target: Path, *, recursive: bool) -> tuple[str, int]:
        args = [self.clamscan_binary, "--no-summary"]
        if recursive and target.is_dir():
            args.append("--recursive")
        args.append(str(target))
        return await self._run_command(args)

    async def _run_command(self, args: Sequence[str]) -> tuple[str, int]:
        command = ["flatpak-spawn", "--host", *args] if self.flatpak_host else list(args)
        process = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(), self.command_timeout)
        except TimeoutError:
            process.kill()
            await process.wait()
            raise
        return stdout.decode("utf-8", errors="replace"), int(process.returncode or 0)

    @staticmethod
    def _result(
        target: Path, started: datetime, output: str, exit_code: int, engine: str
    ) -> ScanResult:
        threats = tuple(
            line.strip()
            for line in output.splitlines()
            if line.strip().endswith("FOUND") or ": " in line and " FOUND" in line
        )
        clean = exit_code == 0 and not threats
        error = (
            None if clean or threats else output.strip() or f"{engine} exited with code {exit_code}"
        )
        return ScanResult(
            target=str(target),
            clean=clean,
            threats=threats,
            engine=engine,
            error=error,
            started_at=started,
            finished_at=datetime.now(UTC),
        )
