"""Hybrid ClamAV engine: clamd UNIX socket first, CLI fallback second."""

from __future__ import annotations

import array
import asyncio
import contextlib
import hashlib
import os
import signal
import socket
import stat
import struct
import threading
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from ..core.base import BaseAVEngine, ScanResult, ScanStatus, compute_file_sha256
from ..core.errors import EngineError
from ..core.profiles import DEFAULT_PROFILE, ScanProfile

#: Grace period given to a subprocess after ``SIGTERM`` before ``SIGKILL``.
TERMINATE_GRACE_SECONDS = 5.0

#: Upper bound for ordinary subprocess output retained in memory (1 MiB).
DEFAULT_MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
_OUTPUT_TRUNCATED_MARKER = "\n[OUTPUT_TRUNCATED]\n"

#: Upper bound for a partial line held while incrementally parsing output.
MAX_OUTPUT_LINE_BYTES = 65536

#: Upper bound for a clamd response buffered in memory (8 MiB).
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

#: Bytes that must never reach the line-oriented clamd command channel.
_CONTROL_BYTES = (b"\x00", b"\n", b"\r")


class _DescriptorSocketControl:
    """Allow cancellation to interrupt a blocking descriptor-scan socket worker."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._socket: socket.socket | None = None
        self._cancelled = False

    def attach(self, sock: socket.socket) -> None:
        with self._lock:
            if self._cancelled:
                reject = True
            else:
                self._socket = sock
                reject = False
        if reject:
            sock.close()
            raise InterruptedError("descriptor scan was cancelled")

    def detach(self, sock: socket.socket) -> None:
        with self._lock:
            if self._socket is sock:
                self._socket = None

    def raise_if_cancelled(self) -> None:
        """Stop the worker at cooperative cancellation boundaries."""
        with self._lock:
            cancelled = self._cancelled
        if cancelled:
            raise InterruptedError("descriptor scan was cancelled")

    def cancel(self) -> None:
        with self._lock:
            self._cancelled = True
            sock = self._socket
            self._socket = None
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            sock.close()


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
        command_inactivity_timeout: float = 600.0,
        command_maximum_timeout: float = 3600.0,
        command_max_output_bytes: int = DEFAULT_MAX_COMMAND_OUTPUT_BYTES,
        max_descriptor_workers: int = 4,
    ) -> None:
        if (
            isinstance(max_descriptor_workers, bool)
            or not isinstance(max_descriptor_workers, int)
            or max_descriptor_workers < 1
        ):
            raise ValueError("max_descriptor_workers must be a positive integer")
        self.socket_path = Path(socket_path)
        self.clamscan_binary = clamscan_binary
        self.freshclam_binary = freshclam_binary
        self.flatpak_host = flatpak_host
        self.command_timeout = command_timeout
        for name, value in (
            ("command_inactivity_timeout", command_inactivity_timeout),
            ("command_maximum_timeout", command_maximum_timeout),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                raise ValueError(f"{name} must be a positive number")
        self.command_inactivity_timeout = float(command_inactivity_timeout)
        self.command_maximum_timeout = float(command_maximum_timeout)
        if (
            isinstance(command_max_output_bytes, bool)
            or not isinstance(command_max_output_bytes, int)
            or command_max_output_bytes < 1
        ):
            raise ValueError("command_max_output_bytes must be a positive integer")
        self.command_max_output_bytes = command_max_output_bytes
        self.max_descriptor_workers = max_descriptor_workers
        self._descriptor_worker_count = 0
        self._descriptor_workers: set[asyncio.Task[tuple[str, int, str]]] = set()
        self._descriptor_workers_lock = threading.Lock()

    def _reserve_descriptor_worker(self) -> bool:
        """Atomically reserve capacity before duplicating or submitting a descriptor."""
        with self._descriptor_workers_lock:
            if self._descriptor_worker_count >= self.max_descriptor_workers:
                return False
            self._descriptor_worker_count += 1
            return True

    def _release_descriptor_worker(self) -> None:
        """Release capacity only after the worker thread has closed its descriptor."""
        with self._descriptor_workers_lock:
            if self._descriptor_worker_count <= 0:
                raise RuntimeError("descriptor worker reservation underflow")
            self._descriptor_worker_count -= 1

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
        if self._has_control_bytes(target):
            return ScanResult(
                target=str(target),
                clean=False,
                status=ScanStatus.ERROR,
                engine=self.name,
                error="Unsupported scan target: control characters in path",
            )
        rejection = self._reject_unsupported_target(target)
        if rejection is not None:
            return rejection
        if profile is None:
            profile = DEFAULT_PROFILE.with_overrides(recursive=recursive)
        else:
            profile.validate()
        started = datetime.now(UTC)
        try:
            initial_file_stat = (
                target.stat(follow_symlinks=False) if target.is_file() else None
            )
        except OSError:
            initial_file_stat = None
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
                return self._finalize(result, target, profile, initial_file_stat)
            except (FileNotFoundError, ConnectionRefusedError):
                # The daemon is genuinely unavailable. A CLI scan is a safe
                # alternative only for this connection-establishment failure.
                pass
            except TimeoutError:
                return self._annotate_profile(
                    ScanResult.timed_out(str(target), started), profile
                )
            except (OSError, ValueError) as exc:
                # A protocol/transport failure after connecting is not proof
                # that clamd is unavailable. Do not silently start a second
                # potentially expensive scan of the same target.
                result = ScanResult(
                    target=str(target),
                    clean=False,
                    status=ScanStatus.ERROR,
                    engine="clamd",
                    error=f"clamd scan failed: {exc}",
                    started_at=started,
                    finished_at=datetime.now(UTC),
                )
                return self._annotate_profile(result, profile)
        try:
            output, exit_code = await self._run_cli_scan(target, profile=profile)
        except TimeoutError:
            # No digest in this case: the engine already gave up on this target,
            # and hashing it afterwards would repeat the very work that timed
            # out (typically a very large or very slow file).
            return self._annotate_profile(ScanResult.timed_out(str(target), started), profile)
        result = self._result(target, started, output, exit_code, "clamscan")
        return self._finalize(result, target, profile, initial_file_stat)


    def _reject_unsupported_target(self, target: Path) -> ScanResult | None:
        """Refuse special targets before any engine backend is invoked.

        Only regular files and directories are meaningful scan targets: reading
        a FIFO blocks until a writer appears, and a character/block device may
        be unbounded. Such targets are reported explicitly as ``ERROR`` instead
        of being handed to ClamAV (M5 "explicit scan target validation").
        """
        if target.is_dir() or target.is_file():
            return None
        return ScanResult(
            target=str(target),
            clean=False,
            status=ScanStatus.ERROR,
            engine=self.name,
            error="Unsupported scan target: not a regular file or directory",
        )

    @staticmethod
    def _has_control_bytes(target: Path) -> bool:
        """Reject targets that could inject a second clamd command.

        The clamd protocol is line-oriented and has no quoting: a newline in
        the path would terminate the ``SCAN``/``CONTSCAN`` command and let an
        attacker-controlled filename issue ``SHUTDOWN``, ``RELOAD`` or an
        additional scan.
        """
        raw = os.fsencode(str(target))
        return any(token in raw for token in _CONTROL_BYTES)

    @staticmethod
    def _annotate_profile(result: ScanResult, profile: ScanProfile) -> ScanResult:
        """Record which scan profile was applied to *result*."""
        result.metadata["profile_id"] = profile.id
        return result

    @staticmethod
    def _same_file_identity(first: os.stat_result, second: os.stat_result) -> bool:
        """Compare identity and mutation-sensitive metadata for a pathname scan."""
        return (
            first.st_dev,
            first.st_ino,
            first.st_size,
            first.st_mtime_ns,
            first.st_ctime_ns,
        ) == (
            second.st_dev,
            second.st_ino,
            second.st_size,
            second.st_mtime_ns,
            second.st_ctime_ns,
        )

    @classmethod
    def _finalize(
        cls,
        result: ScanResult,
        target: Path,
        profile: ScanProfile,
        initial_file_stat: os.stat_result | None = None,
    ) -> ScanResult:
        """Annotate the result and hash only an unchanged single-file target.

        A pathname scan is not bound to an inode. If the file changes or is
        replaced between the scan and digest calculation, its VirusTotal hash
        would not describe the object ClamAV inspected. Such a result is
        therefore marked ERROR and is not enriched with a digest.
        """
        cls._annotate_profile(result, profile)
        if initial_file_stat is None:
            return result

        try:
            before_hash = os.stat(target, follow_symlinks=False)
            if not cls._same_file_identity(initial_file_stat, before_hash):
                raise OSError("target identity or metadata changed during scan")
            sha256 = compute_file_sha256(target)
            after_hash = os.stat(target, follow_symlinks=False)
            if not cls._same_file_identity(initial_file_stat, after_hash):
                raise OSError("target changed while its digest was calculated")
        except OSError as exc:
            metadata = dict(result.metadata)
            metadata.pop("sha256", None)
            metadata["sha256_unavailable_reason"] = str(exc)
            return replace(
                result,
                clean=False,
                status=ScanStatus.ERROR,
                error=f"Target changed during scan; result is not trustworthy: {exc}",
                metadata=metadata,
            )

        if sha256 is not None:
            result.metadata["sha256"] = sha256
        return result

    async def scan_fd(
        self,
        fd: int,
        *,
        target: Path,
        profile: ScanProfile | None = None,
    ) -> ScanResult:
        """Scan the exact opened inode using descriptor-preserving clamd transports.

        FILDES is preferred; INSTREAM reads from the same descriptor when
        FILDES is unavailable. There is never a pathname-based fallback.
        """
        started = datetime.now(UTC)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise OSError("descriptor is not a regular file")
            if profile is None:
                profile = DEFAULT_PROFILE
            else:
                profile.validate()
            if not self.socket_path.exists():
                raise OSError("clamd UNIX socket is unavailable; descriptor scan required")
            if not self._reserve_descriptor_worker():
                result = ScanResult(
                    target=str(target), clean=False, status=ScanStatus.ERROR,
                    engine="clamd-descriptor",
                    error=(
                        "Realtime descriptor scan capacity exhausted "
                        f"(limit: {self.max_descriptor_workers})"
                    ),
                    started_at=started, finished_at=datetime.now(UTC),
                )
                if profile is not None:
                    result.metadata["profile_id"] = profile.id
                return result

            try:
                owned_fd = os.dup(fd)
            except BaseException:
                self._release_descriptor_worker()
                raise

            socket_control = _DescriptorSocketControl()
            worker_coro = asyncio.to_thread(self._scan_fd_owned, owned_fd, socket_control)
            try:
                worker = asyncio.create_task(worker_coro)
            except BaseException:
                worker_coro.close()
                with contextlib.suppress(OSError):
                    os.close(owned_fd)
                self._release_descriptor_worker()
                raise
            with self._descriptor_workers_lock:
                self._descriptor_workers.add(worker)

            def consume_worker_result(task: asyncio.Task[tuple[str, int, str]]) -> None:
                if not task.cancelled():
                    task.exception()
                with self._descriptor_workers_lock:
                    self._descriptor_workers.discard(task)

            worker.add_done_callback(consume_worker_result)

            try:
                output, exit_code, transport = await asyncio.wait_for(
                    asyncio.shield(worker), self.command_timeout
                )
            except TimeoutError:
                socket_control.cancel()
                raise
            except asyncio.CancelledError:
                socket_control.cancel()
                raise
            exit_code = self._descriptor_response_code(output)
            if self._file_identity_changed(before, os.fstat(fd)):
                raise OSError("file changed while clamd was scanning the opened descriptor")
            result = self._result(
                Path(target), started, output, exit_code, f"clamd-{transport}"
            )
            result.metadata["scan_transport"] = transport
            result.metadata["sha256"] = self._sha256_fd(fd)
            if self._file_identity_changed(before, os.fstat(fd)):
                raise OSError("file changed while hashing the opened descriptor")
            result.metadata["profile_id"] = profile.id
            unsupported = self._clamd_unsupported_options(profile)
            if unsupported:
                result.metadata["profile_unsupported_clamd"] = ",".join(unsupported)
            return result
        except TimeoutError as exc:
            result = ScanResult(
                target=str(target), clean=False, status=ScanStatus.TIMEOUT,
                engine="clamd-descriptor",
                error=f"Realtime descriptor scan timed out: {exc}",
                started_at=started, finished_at=datetime.now(UTC),
            )
            if profile is not None:
                result.metadata["profile_id"] = profile.id
            return result
        except (OSError, ValueError) as exc:
            result = ScanResult(
                target=str(target), clean=False, status=ScanStatus.ERROR,
                engine="clamd-descriptor",
                error=f"Realtime descriptor scan rejected: {exc}",
                started_at=started, finished_at=datetime.now(UTC),
            )
            if profile is not None:
                result.metadata["profile_id"] = profile.id
            return result

    @property
    def active_descriptor_worker_count(self) -> int:
        """Return reserved workers, including jobs queued but not yet running."""
        with self._descriptor_workers_lock:
            return self._descriptor_worker_count

    def _scan_fd_owned(
        self, fd: int, socket_control: _DescriptorSocketControl
    ) -> tuple[str, int, str]:
        """Run descriptor scanning and release its reservation after fd cleanup."""
        try:
            return self._scan_fd_sync(fd, socket_control)
        finally:
            try:
                os.close(fd)
            finally:
                self._release_descriptor_worker()

    def _scan_fd_sync(
        self, fd: int, socket_control: _DescriptorSocketControl | None = None
    ) -> tuple[str, int, str]:
        """Use FILDES or INSTREAM while preserving the opened descriptor identity."""
        capabilities = bytearray()
        if socket_control is not None:
            socket_control.raise_if_cancelled()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                if socket_control is not None:
                    socket_control.attach(probe)
                try:
                    probe.settimeout(min(self.command_timeout, 10.0))
                    probe.connect(os.fspath(self.socket_path))
                    probe.sendall(b"nVERSIONCOMMANDS\n")
                    while True:
                        chunk = probe.recv(4096)
                        if not chunk:
                            break
                        capabilities.extend(chunk)
                        if len(capabilities) > 65536:
                            raise ValueError(
                                "clamd VERSIONCOMMANDS response exceeded the size limit"
                            )
                finally:
                    if socket_control is not None:
                        socket_control.detach(probe)
        except (InterruptedError, TimeoutError):
            raise
        except OSError:
            if socket_control is not None:
                socket_control.raise_if_cancelled()
            return self._scan_fd_instream_sync(fd, socket_control)

        if socket_control is not None:
            socket_control.raise_if_cancelled()
        if b"FILDES" not in bytes(capabilities).split():
            return self._scan_fd_instream_sync(fd, socket_control)

        response = bytearray()
        if socket_control is not None:
            socket_control.raise_if_cancelled()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            if socket_control is not None:
                socket_control.attach(sock)
            try:
                sock.settimeout(self.command_timeout)
                sock.connect(os.fspath(self.socket_path))
                if socket_control is not None:
                    socket_control.raise_if_cancelled()
                sock.sendall(b"nFILDES\n")
                rights = array.array("i", [fd]).tobytes()
                # The protocol requires a separate ancillary-data packet with at
                # least one dummy byte after the FILDES command record.
                sock.sendmsg([b" "], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    response.extend(chunk)
                    if len(response) > MAX_RESPONSE_BYTES:
                        raise ValueError("clamd FILDES response exceeded the size limit")
            finally:
                if socket_control is not None:
                    socket_control.detach(sock)
        if socket_control is not None:
            socket_control.raise_if_cancelled()
        output = bytes(response).decode("utf-8", errors="replace")
        if "COMMAND UNAVAILABLE" in output or "UNKNOWN COMMAND" in output:
            if socket_control is not None:
                socket_control.raise_if_cancelled()
            return self._scan_fd_instream_sync(fd, socket_control)
        code = self._descriptor_response_code(output)
        return output, code, "fildes"

    def _scan_fd_instream_sync(
        self, fd: int, socket_control: _DescriptorSocketControl | None = None
    ) -> tuple[str, int, str]:
        """Stream bytes read from the opened descriptor, never from its pathname."""
        response = bytearray()
        if socket_control is not None:
            socket_control.raise_if_cancelled()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            if socket_control is not None:
                socket_control.attach(sock)
            try:
                sock.settimeout(self.command_timeout)
                sock.connect(os.fspath(self.socket_path))
                if socket_control is not None:
                    socket_control.raise_if_cancelled()
                sock.sendall(b"nINSTREAM\n")
                offset = 0
                while True:
                    if socket_control is not None:
                        socket_control.raise_if_cancelled()
                    chunk = os.pread(fd, 65536, offset)
                    if not chunk:
                        break
                    if socket_control is not None:
                        socket_control.raise_if_cancelled()
                    sock.sendall(struct.pack("!I", len(chunk)))
                    sock.sendall(chunk)
                    offset += len(chunk)
                sock.sendall(bytes(4))
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    response.extend(chunk)
                    if len(response) > MAX_RESPONSE_BYTES:
                        raise ValueError("clamd INSTREAM response exceeded the size limit")
            finally:
                if socket_control is not None:
                    socket_control.detach(sock)
        if socket_control is not None:
            socket_control.raise_if_cancelled()
        output = bytes(response).decode("utf-8", errors="replace")
        code = self._descriptor_response_code(output)
        return output, code, "instream"

    @staticmethod
    def _descriptor_response_code(output: str) -> int:
        """Reject empty or unrecognized clamd replies instead of treating them as clean."""
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if not lines:
            raise OSError("clamd returned an empty descriptor-scan response")
        if any("COMMAND UNAVAILABLE" in line or "UNKNOWN COMMAND" in line for line in lines):
            raise OSError("clamd does not support the requested descriptor scan command")
        valid = any(
            line.endswith(" OK") or line.endswith(" FOUND") or line.endswith(" ERROR")
            for line in lines
        )
        if not valid:
            raise OSError("clamd returned an unrecognized descriptor-scan response")
        return 1 if any(line.endswith(" ERROR") for line in lines) else 0

    @staticmethod
    def _file_identity_changed(before: os.stat_result, after: os.stat_result) -> bool:
        return (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        )

    @staticmethod
    def _sha256_fd(fd: int) -> str:
        digest = hashlib.sha256()
        offset = 0
        while True:
            chunk = os.pread(fd, 65536, offset)
            if not chunk:
                break
            digest.update(chunk)
            offset += len(chunk)
        return digest.hexdigest()

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
        if self._has_control_bytes(target):
            # Defence in depth: never write a control character to the
            # line-oriented command channel, even for direct callers.
            raise ValueError("Unsupported scan target: control characters in path")
        unsupported = self._clamd_unsupported_options(profile)
        reader, writer = await asyncio.open_unix_connection(str(self.socket_path))
        try:
            # clamd has no per-connection option channel: recursion is the
            # only profile aspect expressible, via CONTSCAN (recursive scan
            # of a directory) vs SCAN (single file / non-recursive).
            command = b"CONTSCAN" if profile.recursive and target.is_dir() else b"SCAN"
            writer.write(command + b" " + os.fsencode(str(target)) + b"\n")
            await writer.drain()
            # clamd streams one result line per file and closes the connection
            # when the whole command has been served. Reading must therefore
            # continue until EOF: stopping at the first "OK"/"FOUND" line
            # silently discarded every later result of a directory scan.
            response = bytearray()
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                response.extend(chunk)
                if len(response) > MAX_RESPONSE_BYTES:
                    raise ValueError("clamd response exceeded the size limit")
            output = bytes(response).decode("utf-8", errors="replace")
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
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
        except OSError as exc:
            raise EngineError(f"failed to start {command[0]!r}: {exc}") from exc

        assert process.stdout is not None
        assert process.stderr is not None
        retained = bytearray()
        detections: list[str] = []
        detection_set: set[str] = set()
        truncated = False
        loop = asyncio.get_running_loop()
        last_activity = loop.time()

        def parse_line(line: bytes) -> None:
            decoded = line.decode("utf-8", errors="replace").strip()
            if decoded.endswith("FOUND") and ": " in decoded and decoded not in detection_set:
                detection_set.add(decoded)
                detections.append(decoded)

        async def drain(reader: asyncio.StreamReader) -> None:
            nonlocal last_activity, truncated
            pending = bytearray()
            while chunk := await reader.read(65536):
                last_activity = loop.time()
                remaining = self.command_max_output_bytes - len(retained)
                if remaining > 0:
                    retained.extend(chunk[:remaining])
                if len(chunk) > max(remaining, 0):
                    truncated = True

                pending.extend(chunk)
                while True:
                    newline = pending.find(b"\n")
                    if newline < 0:
                        break
                    parse_line(bytes(pending[:newline]))
                    del pending[: newline + 1]
                if len(pending) > MAX_OUTPUT_LINE_BYTES:
                    # ClamAV detection records are short (bounded by filesystem
                    # path and signature lengths); discard oversized non-record
                    # fragments rather than retaining an attacker-controlled line.
                    del pending[: len(pending) - MAX_OUTPUT_LINE_BYTES]
                    truncated = True
            if pending:
                parse_line(bytes(pending))

        readers = [
            asyncio.create_task(drain(process.stdout)),
            asyncio.create_task(drain(process.stderr)),
        ]
        completion = asyncio.gather(process.wait(), *readers)
        started = loop.time()
        try:
            while not completion.done():
                elapsed = loop.time() - started
                inactive = loop.time() - last_activity
                remaining = min(
                    self.command_maximum_timeout - elapsed,
                    self.command_inactivity_timeout - inactive,
                )
                if remaining <= 0:
                    raise TimeoutError(
                        "command exceeded its maximum execution or inactivity timeout"
                    )
                try:
                    await asyncio.wait_for(asyncio.shield(completion), timeout=remaining)
                except TimeoutError:
                    raise TimeoutError(
                        "command exceeded its maximum execution or inactivity timeout"
                    ) from None
            await completion
        except TimeoutError:
            await self._terminate_process(process)
            await asyncio.gather(*readers, return_exceptions=True)
            raise
        except asyncio.CancelledError:
            # Cancellation must reach the subprocess: terminate the process
            # group, finish draining both pipes, and preserve cancellation.
            await self._terminate_process(process)
            await asyncio.gather(*readers, return_exceptions=True)
            raise

        output = bytes(retained).decode("utf-8", errors="replace")
        retained_lines = set(output.splitlines())
        missing_detections = [line for line in detections if line not in retained_lines]
        if missing_detections:
            output += ("\n" if output and not output.endswith("\n") else "") + "\n".join(
                missing_detections
            )
        if truncated:
            output += _OUTPUT_TRUNCATED_MARKER
        return output, int(process.returncode or 0)

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
    def _detection_lines(output: str) -> tuple[str, ...]:
        """Extract the canonical ``<path>: <signature> FOUND`` detection lines.

        Both clamd and clamscan emit one such line per detection, so the line
        must end with ``FOUND`` *and* carry the ``": "`` separator. Matching on
        the bare substring ``" FOUND"`` made a clean path like
        ``/tmp/my FOUND report.txt: OK`` look like a threat.
        """
        return tuple(
            line.strip()
            for line in output.splitlines()
            if line.strip().endswith("FOUND") and ": " in line
        )

    @staticmethod
    def _result(
        target: Path, started: datetime, output: str, exit_code: int, engine: str
    ) -> ScanResult:
        threats = ClamAVEngine._detection_lines(output)
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
        result = ScanResult(
            target=str(target),
            clean=status is ScanStatus.CLEAN,
            status=status,
            threats=threats,
            engine=engine,
            error=error,
            started_at=started,
            finished_at=datetime.now(UTC),
        )
        if _OUTPUT_TRUNCATED_MARKER in output:
            result.metadata["output_truncated"] = True
        return result
