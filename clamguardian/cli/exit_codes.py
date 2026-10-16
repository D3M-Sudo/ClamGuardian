"""Centralized CLI exit codes.

The whole CLI maps every terminal condition to exactly one of these codes;
command handlers must never invent their own values.

Policy (documented in ``docs/design/cli.md``):

=====  ============================================
Code   Meaning
=====  ============================================
0      Scan completed successfully / clean
1      Scan completed and threats detected
2      Usage / CLI argument error (also argparse)
3      Engine or runtime error
4      Scan timed out
5      Scan cancelled by the user (Ctrl+C)
=====  ============================================
"""

from __future__ import annotations

EXIT_OK = 0
EXIT_INFECTED = 1
EXIT_USAGE = 2
EXIT_ENGINE_ERROR = 3
EXIT_TIMEOUT = 4
EXIT_CANCELLED = 5

__all__ = [
    "EXIT_CANCELLED",
    "EXIT_ENGINE_ERROR",
    "EXIT_INFECTED",
    "EXIT_OK",
    "EXIT_TIMEOUT",
    "EXIT_USAGE",
]
