"""Desktop application settings (UI-agnostic, stdlib only)."""
from __future__ import annotations

import contextlib
import json
import os
import tempfile
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ..history.backend import default_history_db_path
from .profiles import DEFAULT_REGISTRY, resolve_profile

__all__ = [
    "DEFAULT_PROFILE_ID", "SETTINGS_FILE_MODE", "SETTINGS_FILE_NAME",
    "VALID_COLOR_SCHEMES", "AppSettings", "SettingsStore",
    "default_settings_path", "profile_index",
]
DEFAULT_PROFILE_ID = "quick"
VALID_COLOR_SCHEMES: tuple[str, ...] = ("system", "light", "dark")
SETTINGS_FILE_NAME = "settings.json"
SETTINGS_FILE_MODE = 0o600


@dataclass(frozen=True, slots=True)
class AppSettings:
    default_profile_id: str = DEFAULT_PROFILE_ID
    notifications_enabled: bool = True
    color_scheme: str = "system"
    usb_autoscan_enabled: bool = False
    intelligence_enabled: bool = False
    intelligence_profile: str = "public"
    realtime_enabled: bool = False
    realtime_paths: tuple[str, ...] = ()
    scheduled_scans_enabled: bool = False
    scheduled_hour: int = 2
    scheduled_minute: int = 0
    autostart_enabled: bool = False

    def normalized(self) -> AppSettings:
        profile_id = self.default_profile_id
        if resolve_profile(profile_id) is None:
            profile_id = DEFAULT_PROFILE_ID
        scheme = self.color_scheme if self.color_scheme in VALID_COLOR_SCHEMES else "system"
        try:
            intel_profile = self.intelligence_profile if self.intelligence_profile in {"public", "premium"} else "public"
        except ValueError:
            intel_profile = APIProfile.PUBLIC.value
        return AppSettings(
            default_profile_id=profile_id,
            notifications_enabled=bool(self.notifications_enabled),
            color_scheme=scheme,
            usb_autoscan_enabled=bool(self.usb_autoscan_enabled),
            intelligence_enabled=bool(self.intelligence_enabled),
            intelligence_profile=intel_profile,
            realtime_enabled=bool(self.realtime_enabled),
            realtime_paths=tuple(str(p) for p in self.realtime_paths),
            scheduled_scans_enabled=bool(self.scheduled_scans_enabled),
            scheduled_hour=int(self.scheduled_hour) % 24,
            scheduled_minute=int(self.scheduled_minute) % 60,
            autostart_enabled=bool(self.autostart_enabled),
        )


def default_settings_path() -> Path:
    return default_history_db_path().parent / SETTINGS_FILE_NAME


def profile_index(profile_id: str | None) -> int:
    profiles = DEFAULT_REGISTRY.list()
    ids = [profile.id for profile in profiles]
    return ids.index(profile_id) if profile_id in ids else ids.index(DEFAULT_PROFILE_ID)


def _settings_from_mapping(raw: Mapping[str, Any]) -> AppSettings:
    profile = raw.get("default_profile_id", DEFAULT_PROFILE_ID)
    notifications = raw.get("notifications_enabled", True)
    scheme = raw.get("color_scheme", "system")
    usb = raw.get("usb_autoscan_enabled", False)
    intel = raw.get("intelligence_enabled", False)
    intel_profile = raw.get("intelligence_profile", "public")
    rt = raw.get("realtime_enabled", False)
    rt_paths = raw.get("realtime_paths", ())
    sched = raw.get("scheduled_scans_enabled", False)
    s_hour = raw.get("scheduled_hour", 2)
    s_min = raw.get("scheduled_minute", 0)
    autostart = raw.get("autostart_enabled", False)
    paths_tuple = tuple(str(p) for p in rt_paths) if isinstance(rt_paths, (list, tuple)) else ()
    return AppSettings(
        default_profile_id=profile if isinstance(profile, str) else DEFAULT_PROFILE_ID,
        notifications_enabled=notifications if isinstance(notifications, bool) else True,
        color_scheme=scheme if isinstance(scheme, str) else "system",
        usb_autoscan_enabled=usb if isinstance(usb, bool) else False,
        intelligence_enabled=intel if isinstance(intel, bool) else False,
        intelligence_profile=intel_profile if isinstance(intel_profile, str) else "public",
        realtime_enabled=rt if isinstance(rt, bool) else False,
        realtime_paths=paths_tuple,
        scheduled_scans_enabled=sched if isinstance(sched, bool) else False,
        scheduled_hour=int(s_hour) if isinstance(s_hour, int) else 2,
        scheduled_minute=int(s_min) if isinstance(s_min, int) else 0,
        autostart_enabled=autostart if isinstance(autostart, bool) else False,
    ).normalized()


class SettingsStore:
    def __init__(self, path: Path | None = None) -> None:
        self._path = Path(path) if path is not None else default_settings_path()

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> AppSettings:
        try:
            parsed = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return AppSettings().normalized()
        return _settings_from_mapping(parsed) if isinstance(parsed, dict) else AppSettings().normalized()

    def save(self, settings: AppSettings) -> AppSettings:
        normalized = settings.normalized()
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            dir=self._path.parent, prefix=f".{self._path.name}.", suffix=".tmp"
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(asdict(normalized), handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, SETTINGS_FILE_MODE)
            os.replace(temporary, self._path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(temporary)
            raise
        return normalized
