"""Shared probe for real GTK widget construction in tests.

GTK4 can abort or segfault the interpreter when no display or no usable
backend is available. Probing in the pytest process therefore kills the
whole run during collection, before any test executes. This probe runs the
construction in a throwaway subprocess: a crash only fails the probe and
the affected tests are skipped.
"""

from __future__ import annotations

import os
import subprocess
import sys
from functools import lru_cache

from clamguardian.ui import GTK_AVAILABLE

_PROBE_CODE = """
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

Gtk.Box()
Adw.StatusPage()
"""


@lru_cache(maxsize=1)
def gtk_works() -> bool:
    """Return whether GTK widgets can actually be constructed in this env.

    Requires PyGObject, a display (``DISPLAY``/``WAYLAND_DISPLAY``) and a
    working GTK backend. The probe is cached: it runs at most once per
    pytest session.
    """
    if not GTK_AVAILABLE:
        return False
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return False
    env = {**os.environ, "GTK_A11Y": "none"}
    try:  # pragma: no cover - needs a real display/X server
        completed = subprocess.run(
            [sys.executable, "-c", _PROBE_CODE],
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - env issue
        return False
    return completed.returncode == 0
