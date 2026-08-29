"""ClamGuardian CLI entry point and command implementations.

Responsibilities of this module (and of the whole :mod:`clamguardian.cli`
package) are strictly limited to:

* argument parsing and usage validation;
* target existence validation (read-only, mirroring the engine's contract);
* resolving profiles through :data:`~clamguardian.core.profiles.DEFAULT_REGISTRY`;
* driving the event loop with a thin synchronous entry point;
* presenting results (human or JSON).

Scan orchestration is delegated entirely to the Core:
``ScanProfileRegistry`` → ``ScanTaskRunner`` → ``BaseAVEngine``. The CLI
never spawns subprocesses, never touches clamd, and never builds ClamAV
arguments.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import sys
from pathlib import Path
from typing import IO, TYPE_CHECKING

from .. import __version__
from ..core.base import BaseAVEngine, ScanResult
from ..core.errors import ClamGuardianError, ProfileError
from ..core.profiles import DEFAULT_PROFILE, DEFAULT_REGISTRY, ScanProfile
from ..core.runner import ScanTaskRunner
from ..engines.clamav import ClamAVEngine
from .exit_codes import (
    EXIT_CANCELLED,
    EXIT_ENGINE_ERROR,
    EXIT_INFECTED,
    EXIT_OK,
    EXIT_TIMEOUT,
    EXIT_USAGE,
)
from .output import cancelled_payload, format_human, format_profiles, result_to_payload

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Sequence

__all__ = ["build_parser", "main", "run"]


class _Streams:
    """Output streams bundle (stdout/stderr) for testability."""

    def __init__(self, out: IO[str], err: IO[str]) -> None:
        self.out = out
        self.err = err


def _default_engine() -> BaseAVEngine:
    """Return the production engine (kept indirection-friendly for tests)."""
    return ClamAVEngine()


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the whole CLI."""
    parser = argparse.ArgumentParser(
        prog="clamguardian",
        description="ClamGuardian — ClamAV security framework command-line interface.",
        epilog=(
            "Exit codes: 0 clean/ok, 1 threats detected, 2 usage error, "
            "3 engine/runtime error, 4 timeout, 5 cancelled (Ctrl+C)."
        ),
    )
    parser.add_argument("--version", action="version", version=f"ClamGuardian {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    scan = sub.add_parser(
        "scan",
        help="scan a file or directory",
        description="Scan a file or directory with the ClamAV engine.",
        epilog=(
            "Profiles are resolved from the Core registry "
            "(clamguardian.core.profiles): quick, home, full, custom. "
            "Without --profile the Core default profile is used "
            "(id: 'default', Standard Scan)."
        ),
    )
    scan.add_argument("path", metavar="PATH", help="file or directory to scan")
    scan.add_argument(
        "--profile",
        metavar="PROFILE",
        default=None,
        help="scan profile id from the Core registry (default: core default profile)",
    )
    scan.add_argument(
        "--json",
        action="store_true",
        help="emit a machine-readable JSON report on stdout (diagnostics on stderr)",
    )
    scan.set_defaults(func=_cmd_scan)

    profiles_cmd = sub.add_parser(
        "profiles",
        help="list available scan profiles",
        description="List the scan profiles registered in the Core registry.",
    )
    profiles_cmd.add_argument(
        "--json", action="store_true", help="emit the profile list as JSON on stdout"
    )
    profiles_cmd.set_defaults(func=_cmd_profiles)

    version_cmd = sub.add_parser(
        "version",
        help="print the ClamGuardian version",
        description="Print the ClamGuardian version (single source of truth).",
    )
    version_cmd.set_defaults(func=_cmd_version)

    return parser


def _cmd_version(args: argparse.Namespace, streams: _Streams) -> int:
    del args
    print(f"ClamGuardian {__version__}", file=streams.out)
    return EXIT_OK


def _cmd_profiles(args: argparse.Namespace, streams: _Streams) -> int:
    profiles = DEFAULT_REGISTRY.list()
    if args.json:
        payload = [
            {"id": profile.id, "name": profile.name, "description": profile.description}
            for profile in profiles
        ]
        print(json.dumps(payload, indent=2), file=streams.out)
    else:
        print(format_profiles(profiles), file=streams.out)
    return EXIT_OK


def _resolve_profile(profile_id: str | None, streams: _Streams) -> ScanProfile | None:
    """Resolve the profile via the Core registry; report errors on stderr."""
    if profile_id is None:
        return DEFAULT_PROFILE
    try:
        return DEFAULT_REGISTRY.get(profile_id)
    except ProfileError as exc:
        print(f"error: {exc}", file=streams.err)
        return None


def _validate_target(raw: str, streams: _Streams) -> Path | None:
    """Validate the scan target without bypassing Core/Engine policies.

    The check mirrors the engine's own ``resolve(strict=True)`` contract so
    the user gets an immediate, readable error for missing/unreadable
    targets. The resolved Path is what the Core receives: the CLI never
    rewrites it into shell strings and never spawns anything.
    """
    target = Path(raw)
    try:
        return target.expanduser().resolve(strict=True)
    except FileNotFoundError:
        print(f"error: target does not exist: {raw}", file=streams.err)
    except PermissionError:
        print(f"error: permission denied: {raw}", file=streams.err)
    except OSError as exc:
        print(f"error: invalid target {raw}: {exc}", file=streams.err)
    return None


def _report_result(
    result: ScanResult, profile_id: str, args: argparse.Namespace, streams: _Streams
) -> int:
    """Print the terminal result and map it to the documented exit code."""
    if args.json:
        print(json.dumps(result_to_payload(result, profile_id)), file=streams.out)
    else:
        print(format_human(result), file=streams.out)
    status = result.status.value
    if status == "infected":
        return EXIT_INFECTED
    if status == "timeout":
        return EXIT_TIMEOUT
    if status == "cancelled":
        return EXIT_CANCELLED
    if status == "error":
        return EXIT_ENGINE_ERROR
    return EXIT_OK


def _run_scan(
    engine: BaseAVEngine,
    target: Path,
    profile: ScanProfile,
    args: argparse.Namespace,
    streams: _Streams,
) -> int:
    """Drive one scan through the Core runner, handling cancellation."""
    profile_id = profile.id
    runner = ScanTaskRunner(engine, max_concurrency=1)
    if not args.json:
        print(f"ClamGuardian\nProfile: {profile.name}\nTarget: {target}", file=streams.out)
        print("Scanning...", file=streams.out)
    try:
        result = asyncio.run(runner.submit(target, profile=profile))
    except KeyboardInterrupt:
        # asyncio.run cancelled the main task: the engine's cancellation
        # lifecycle (SIGTERM process group → grace → SIGKILL → wait) has
        # already reaped the ClamAV subprocess. Never convert this into a
        # generic error.
        print("Scan cancelled by user", file=streams.err)
        if args.json:
            print(json.dumps(cancelled_payload(str(target), profile_id)), file=streams.out)
        return EXIT_CANCELLED
    except asyncio.CancelledError:
        print("Scan cancelled", file=streams.err)
        return EXIT_CANCELLED
    except ProfileError as exc:
        print(f"error: {exc}", file=streams.err)
        return EXIT_USAGE
    except ClamGuardianError as exc:
        print(f"error: engine failure: {exc}", file=streams.err)
        return EXIT_ENGINE_ERROR
    return _report_result(result, profile_id, args, streams)


def _cmd_scan(args: argparse.Namespace, streams: _Streams) -> int:
    profile = _resolve_profile(args.profile, streams)
    if profile is None:
        return EXIT_USAGE
    target = _validate_target(args.path, streams)
    if target is None:
        return EXIT_ENGINE_ERROR
    return _run_scan(_default_engine(), target, profile, args, streams)


def run(
    argv: Sequence[str] | None = None,
    *,
    out: IO[str] | None = None,
    err: IO[str] | None = None,
) -> int:
    """Parse *argv*, dispatch the command and return the exit code.

    When custom streams are provided, ``sys.stdout``/``sys.stderr`` are
    temporarily redirected so argparse's own output (``--help``,
    ``--version``, usage errors) lands in the same streams too.
    """
    streams = _Streams(
        out if out is not None else sys.stdout, err if err is not None else sys.stderr
    )
    context = (
        contextlib.redirect_stdout(streams.out)
        if out is not None
        else contextlib.nullcontext()
    )
    with context:
        args = build_parser().parse_args(argv)
        handler = args.func
        try:
            return handler(args, streams)
        except KeyboardInterrupt:  # pragma: no cover - depends on tty timing
            print("interrupted", file=streams.err)
            return EXIT_CANCELLED


def main() -> None:
    """Console-script entry point: thin synchronous wrapper around run()."""
    raise SystemExit(run())


if __name__ == "__main__":  # pragma: no cover
    main()
