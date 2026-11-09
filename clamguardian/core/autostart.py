"""Automatic user-session startup management (XDG autostart)."""

from __future__ import annotations

import contextlib
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

AUTOSTART_DIR = Path.home() / ".config" / "autostart"
DESKTOP_ENTRY_NAME = "io.github.clamguardian.ClamGuardian.desktop"

DESKTOP_ENTRY_TEMPLATE = """[Desktop Entry]
Type=Application
Name=ClamGuardian
Comment=On-demand and realtime antivirus scanning powered by ClamAV
Exec=clamguardian ui
Icon=io.github.clamguardian.ClamGuardian
Terminal=false
Categories=Utility;Security;
StartupNotify=false
X-GNOME-Autostart-enabled=true
"""


class AutostartManager:
    """Manage unprivileged user-session autostart via ~/.config/autostart desktop entry."""

    def __init__(self, autostart_dir: Path | None = None) -> None:
        self.autostart_dir = autostart_dir or AUTOSTART_DIR
        self.entry_path = self.autostart_dir / DESKTOP_ENTRY_NAME

    def is_enabled(self) -> bool:
        """Check if user-session autostart desktop entry exists."""
        return self.entry_path.is_file()

    def enable(self) -> None:
        """Install user-session autostart desktop entry."""
        self.autostart_dir.mkdir(parents=True, exist_ok=True)
        self.entry_path.write_text(DESKTOP_ENTRY_TEMPLATE, encoding="utf-8")
        with contextlib.suppress(OSError):
            os.chmod(self.entry_path, 0o644)

    def disable(self) -> None:
        """Remove user-session autostart desktop entry."""
        if self.entry_path.exists():
            with contextlib.suppress(OSError):
                self.entry_path.unlink()
