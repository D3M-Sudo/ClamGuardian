"""Reproduce AUD-01: the clamd client stops reading after the first result line.

Evidence script for ``docs/reports/INDEPENDENT-AUDIT-2026-10-19.md``. It starts a
local UNIX socket that behaves like ``clamd`` (one result line per file, then a
summary) and drives the real :class:`ClamAVEngine` against it. No ClamAV
installation is required.

Run from the repository root::

    PYTHONPATH=. python3 docs/validation/repro-clamd-multiline.py

Expected output on the audited code (bug present)::

    status: clean | threats: ()
    clean flag: True | engine: clamd

Expected output after the remediation: ``status: infected`` with the ``FOUND``
line in ``threats``.
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import types
from pathlib import Path


def _install_cryptography_stub() -> None:
    """Allow importing the package on a host without third-party wheels."""
    try:
        import cryptography  # noqa: F401
    except ModuleNotFoundError:
        for name in (
            "cryptography",
            "cryptography.hazmat",
            "cryptography.hazmat.primitives",
            "cryptography.hazmat.primitives.ciphers",
            "cryptography.hazmat.primitives.ciphers.aead",
        ):
            sys.modules.setdefault(name, types.ModuleType(name))
        sys.modules["cryptography.hazmat.primitives.ciphers.aead"].AESGCM = object


_install_cryptography_stub()

from clamguardian.core.profiles import DEFAULT_PROFILE  # noqa: E402
from clamguardian.engines.clamav import ClamAVEngine  # noqa: E402

_LINES = [
    b"/scan/clean-a.txt: OK\n",
    b"/scan/clean-b.txt: OK\n",
    b"/scan/eicar.txt: Eicar-Test-Signature FOUND\n",
    b"\n----------- SCAN SUMMARY -----------\nInfected files: 1\n",
]


async def start_fake_clamd(socket_path: Path, captured: list[bytes]):
    """Serve one clamd command, streaming ``_LINES`` like the real daemon."""

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        captured.append(await reader.readline())
        for line in _LINES:
            writer.write(line)
            await writer.drain()
            await asyncio.sleep(0.05)
        writer.close()
        await writer.wait_closed()

    return await asyncio.start_unix_server(handle, path=str(socket_path))


async def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        socket_path = root / "clamd.ctl"
        captured: list[bytes] = []

        server = await start_fake_clamd(socket_path, captured)
        async with server:
            engine = ClamAVEngine(socket_path=socket_path, command_timeout=5)
            profile = DEFAULT_PROFILE.with_overrides(recursive=True)
            output, code, _ = await engine._scan_socket(root, profile)
            print("=== CASE 1: multi-file directory scan ===")
            print("returned output:", repr(output))
            print("returned exit code:", code)
            print("expected FOUND line present:", "FOUND" in output)

            result = await engine.scan(root)
            print("\n=== CASE 3: end-to-end engine.scan(directory) ===")
            print("status:", result.status.value, "| threats:", result.threats)
            print("clean flag:", result.clean, "| engine:", result.engine)

        injected = root / "evil\nSHUTDOWN"
        injected.write_bytes(b"x")
        captured.clear()
        server = await start_fake_clamd(socket_path, captured)
        async with server:
            engine = ClamAVEngine(socket_path=socket_path, command_timeout=5)
            await engine._scan_socket(injected, DEFAULT_PROFILE)
        print("\n=== CASE 2: newline injection into the clamd command channel ===")
        print("bytes received by fake clamd:", captured[0] if captured else None)


if __name__ == "__main__":
    asyncio.run(main())
