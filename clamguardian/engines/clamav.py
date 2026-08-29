"""Hybrid ClamAV engine: clamd UNIX socket first, CLI fallback second."""

from __future__ import annotations

import asyncio
import os
import signal
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from ..core.base import BaseAVEngine, ScanResult, ScanStatus
from ..core.errors import EngineError

#: Grace period given to a subprocess after ``SIGTERM`` before ``SIGKILL``.
TERMINATE_GRACE_SECONDS = 5.0


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
        try:
            output, exit_code = await self._run_cli_scan(target, recursive=recursive)
        except TimeoutError:
            return ScanResult.timed_out(str(target), started)
        return self._result(target, started, output, exit_code, "clamscan")

    async def update_signatures(self) -> str:
        """Run freshclam using the host when Flatpak integration is enabled."""
        output, code = await self._run_command([self.freshclam_binary])
        if code != 0:
            raise EngineError(f"freshclam failed with exit code {code}: {output.strip()}")
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
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                start_new_session=True,
            )
        except OSError as exc:
            raise EngineError(f"failed to start {command[0]!r}: {exc}") from exc
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(), self.command_timeout)
        except TimeoutError:
            await self._terminate_process(process)
            raise
        except asyncio.CancelledError:
            # Cancellation must reach the subprocess: terminate the whole
            # process group started with ``start_new_session=True``, wait for
            # it to die, then re-raise so the caller still observes the
            # CancelledError (never a generic failure).
            await self._terminate_process(process)
            raise
        return stdout.decode("utf-8", errors="replace"), int(process.returncode or 0)

    @staticmethod
    async def _terminate_process(
        process: asyncio.subprocess.Process, grace: float = TERMINATE_GRACE_SECONDS
    ) -> None:
        """Deterministically reap *process*: terminate, kill, then wait.

        Safe to call on an already-exited process and never kills twice.
        Because subprocesses run in their own session (``start_new_session``),
        the signal targets the whole process group so ClamAV helper children
        cannot survive as orphans.
        """
        if process.returncode is not None:
            return  # already exited: nothing to reap
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            try:
                process.terminate()
            except ProcessLookupError:
                return
        try:
            await asyncio.wait_for(process.wait(), grace)
        except TimeoutError:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                process.kill()
            await process.wait()

    @staticmethod
    def _result(
        target: Path, started: datetime, output: str, exit_code: int, engine: str
    ) -> ScanResult:
        threats = tuple(
            line.strip()
            for line in output.splitlines()
            if line.strip().endswith("FOUND") or ": " in line and " FOUND" in line
        )
        if exit_code == 0 and not threats:
            status = ScanStatus.CLEAN
        elif threats:
            status = ScanStatus.INFECTED
        else:
            status = ScanStatus.ERROR
        error = (
            None
            if status in (ScanStatus.CLEAN, ScanStatus.INFECTED)
            else output.strip() or f"{engine} exited with code {exit_code}"
        )
        return ScanResult(
            target=str(target),
            clean=status is ScanStatus.CLEAN,
            status=status,
            threats=threats,
            engine=engine,
            error=error,
            started_at=started,
            finished_at=datetime.now(UTC),
        )
