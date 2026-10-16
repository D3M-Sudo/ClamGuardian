"""Command-line interface for ClamGuardian.

The CLI is a thin front-end over the Core API: it only performs argument
parsing, target validation and output presentation. All scan orchestration
lives in :mod:`clamguardian.core` (profiles, runner) and
:mod:`clamguardian.engines` (ClamAV); the CLI never touches subprocesses,
clamd sockets or ClamAV CLI flags directly.
"""

from .exit_codes import (
    EXIT_CANCELLED,
    EXIT_ENGINE_ERROR,
    EXIT_INFECTED,
    EXIT_OK,
    EXIT_TIMEOUT,
    EXIT_USAGE,
)
from .main import build_parser, run

__all__ = [
    "EXIT_CANCELLED",
    "EXIT_ENGINE_ERROR",
    "EXIT_INFECTED",
    "EXIT_OK",
    "EXIT_TIMEOUT",
    "EXIT_USAGE",
    "build_parser",
    "run",
]
