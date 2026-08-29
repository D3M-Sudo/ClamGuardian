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
from ..core.profiles import DEFAULT_PROFILE, ScanProfile

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

    async def scan(
        self,
        target: Path,
        *,
        recursive: bool = True,
        profile: ScanProfile | None = None,
    ) -> ScanResult:
        """Scan *target*, preferring clamd and falling back to clamscan.

        ``profile=None`` preserves the pre-M2 behaviour: the engine default
        profile is applied (recursion driven by ``recursive``).
        """
        target = Path(target).expanduser().resolve(strict=True)
        if profile is None:
            profile = DEFAULT_PROFILE.with_overrides(recursive=recursive)
        else:
            profile.validate()
        started = datetime.now(UTC)
        if self.socket_path.exists():
            try:
                output, exit_code, unsupported = await asyncio.wait_for(
                    self._scan_socket(target, profile), self.command_timeout
                )
                result = self._result(target, started, output, exit_code, "clamd")
                # Explicit policy for options clamd cannot honour per
                # connection (they are clamd.conf server-side settings):
                # never silently ignored, always reported in metadata.
                if unsupported:
                    result.metadata["profile_unsupported_clamd"] = ",".join(unsupported)
                result.metadata["profile_id"] = profile.id
                return result
            except (TimeoutError, OSError, ValueError):
                pass
        try:
            output, exit_code = await self._run_cli_scan(target, profile=profile)
        except TimeoutError:
            return ScanResult.timed_out(str(target), started)
        result = self._result(target, started, output, exit_code, "clamscan")
        result.metadata["profile_id"] = profile.id
        return result

    async def update_signatures(self) -> str:
        """Run freshclam using the host when Flatpak integration is enabled."""
        output, code = await self._run_command([self.freshclam_binary])
        if code != 0:
            raise EngineError(f"freshclam failed with exit code {code}: {output.strip()}")
        return output.strip()

    async def _scan_socket(
        self, target: Path, profile: ScanProfile
    ) -> tuple[str, int, tuple[str, ...]]:
        """Run a clamd scan; return (output, code, unsupported-profile-options)."""
        unsupported = self._clamd_unsupported_options(profile)
        reader, writer = await asyncio.open_unix_connection(str(self.socket_path))
        try:
            # clamd has no per-connection option channel: recursion is the
            # only profile aspect expressible, via CONTSCAN (recursive scan
            # of a directory) vs SCAN (single file / non-recursive).
            command = b"CONTSCAN" if profile.recursive and target.is_dir() else b"SCAN"
            writer.write(command + b" " + os.fsencode(str(target)) + b"\n")
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
            return output, code, unsupported
        finally:
            writer.close()
            await writer.wait_closed()

    @staticmethod
    def _clamd_unsupported_options(profile: ScanProfile) -> tuple[str, ...]:
        """Profile options clamd cannot honour per connection.

        These are *not* dropped silently: the caller records them in
        ``ScanResult.metadata["profile_unsupported_clamd"]`` so front-ends can
        inform the user that the daemon's clamd.conf governs them.
        """
        unsupported: list[str] = []
        if not profile.scan_archives:
            unsupported.append("scan_archives")
        if not profile.scan_mail:
            unsupported.append("scan_mail")
        if profile.detect_pua:
            unsupported.append("detect_pua")
        if profile.max_filesize_mib is not None:
            unsupported.append("max_filesize_mib")
        if profile.max_scansize_mib is not None:
            unsupported.append("max_scansize_mib")
        if profile.max_recursion is not None:
            unsupported.append("max_recursion")
        if profile.max_files is not None:
            unsupported.append("max_files")
        if profile.follow_symlinks is not None:
            unsupported.append("follow_symlinks")
        return tuple(unsupported)

    @staticmethod
    def _clamscan_args(profile: ScanProfile) -> list[str]:
        """Translate a :class:`ScanProfile` into clamscan CLI arguments.

        This is the single place where semantic profile options become
        engine-specific strings; front-ends never see these.
        """
        args: list[str] = []
        if profile.recursive:
            args.append("--recursive")
        if profile.scan_archives:
            args.append("--scan-archive=yes")
        else:
            args.append("--scan-archive=no")
        if profile.scan_mail:
            args.append("--scan-mail=yes")
        else:
            args.append("--scan-mail=no")
        if profile.detect_pua:
            args.append("--pua")
        if profile.max_filesize_mib is not None:
            args.append(f"--max-filesize={profile.max_filesize_mib}M")
        if profile.max_scansize_mib is not None:
            args.append(f"--max-scansize={profile.max_scansize_mib}M")
        if profile.max_recursion is not None:
            args.append(f"--max-recursion={profile.max_recursion}")
        if profile.max_files is not None:
            args.append(f"--max-files={profile.max_files}")
        if profile.follow_symlinks is True:
            args.append("--follow-symlinks")
        elif profile.follow_symlinks is False:
            args.append("--nofollow-symlinks")
        return args

    async def _run_cli_scan(self, target: Path, *, profile: ScanProfile) -> tuple[str, int]:
        args = [self.clamscan_binary, "--no-summary", *self._clamscan_args(profile), str(target)]
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
