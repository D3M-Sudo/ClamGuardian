"""Desktop application settings (UI-agnostic, stdlib only).

The desktop shell needs a handful of user preferences that must survive a
restart: the default scan profile, whether desktop notifications are sent and
which colour scheme to request.  They live in a small JSON file under the
application data directory so the same store works inside and outside the
Flatpak sandbox (where ``$XDG_DATA_HOME`` points at the granted app-data
path).

The module deliberately has no GTK/PyGObject dependency: it is imported by
the headless test suite and by the pure-logic layer of the UI, exactly like
:mod:`clamguardian.core.diagnostics`.

Failure policy: :meth:`SettingsStore.load` is *tolerant* (a missing, corrupt
or partially invalid file degrades to defaults) because a broken preference
file must never prevent the application from starting.
:meth:`SettingsStore.save` is *strict* and lets :class:`OSError` propagate so
the caller can surface a real write failure instead of silently losing the
user's choice.
"""

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
    "DEFAULT_PROFILE_ID",
    "SETTINGS_FILE_MODE",
    "SETTINGS_FILE_NAME",
    "VALID_COLOR_SCHEMES",
    "AppSettings",
    "SettingsStore",
    "default_settings_path",
    "profile_index",
]

#: Profile preselected on a fresh installation.  ``DEFAULT_REGISTRY.list()``
#: is ordered by id (custom, full, home, quick), so index 0 is *not* a sane
#: default; the settings store fixes that explicitly.
DEFAULT_PROFILE_ID = "quick"

#: Colour schemes understood by the settings page (mapped to Adw.StyleManager).
VALID_COLOR_SCHEMES: tuple[str, ...] = ("system", "light", "dark")

#: File name inside the application data directory.
SETTINGS_FILE_NAME = "settings.json"

#: Owner-only permissions for the settings file.
SETTINGS_FILE_MODE = 0o600


@dataclass(frozen=True, slots=True)
class AppSettings:
    """User-visible desktop preferences."""

    default_profile_id: str = DEFAULT_PROFILE_ID
    notifications_enabled: bool = True
    color_scheme: str = "system"

    def normalized(self) -> AppSettings:
        """Return a copy with every field forced into a valid state.

        Unknown profile ids fall back to :data:`DEFAULT_PROFILE_ID` and an
        unknown colour scheme falls back to ``"system"``; values loaded from
        disk are therefore never trusted verbatim.
        """
        profile_id = self.default_profile_id
        if resolve_profile(profile_id) is None:
            profile_id = DEFAULT_PROFILE_ID
        scheme = self.color_scheme if self.color_scheme in VALID_COLOR_SCHEMES else "system"
        return AppSettings(
            default_profile_id=profile_id,
            notifications_enabled=bool(self.notifications_enabled),
            color_scheme=scheme,
        )


def default_settings_path() -> Path:
    """Resolve the default settings file next to ``history.db``."""
    return default_history_db_path().parent / SETTINGS_FILE_NAME


def profile_index(profile_id: str | None) -> int:
    """Return the combo index for *profile_id* in the registry order.

    ``DEFAULT_REGISTRY.list()`` is sorted by id (custom, full, home, quick),
    so the first entry is not a sensible default.  Unknown ids fall back to
    the index of :data:`DEFAULT_PROFILE_ID`.
    """
    profiles = DEFAULT_REGISTRY.list()
    ids = [profile.id for profile in profiles]
    if profile_id in ids:
        return ids.index(profile_id)
    return ids.index(DEFAULT_PROFILE_ID)


def _settings_from_mapping(raw: Mapping[str, Any]) -> AppSettings:
    """Build settings from an arbitrary JSON mapping, ignoring bad types."""
    profile = raw.get("default_profile_id", DEFAULT_PROFILE_ID)
    notifications = raw.get("notifications_enabled", True)
    scheme = raw.get("color_scheme", "system")
    return AppSettings(
        default_profile_id=profile if isinstance(profile, str) else DEFAULT_PROFILE_ID,
        notifications_enabled=(
            notifications if isinstance(notifications, bool) else True
        ),
        color_scheme=scheme if isinstance(scheme, str) else "system",
    ).normalized()


class SettingsStore:
    """Load and persist :class:`AppSettings` as owner-only JSON."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = Path(path) if path is not None else default_settings_path()

    @property
    def path(self) -> Path:
        """The settings file location."""
        return self._path

    def load(self) -> AppSettings:
        """Return persisted settings, or defaults when the file is unusable."""
        try:
            text = self._path.read_text(encoding="utf-8")
            parsed = json.loads(text)
        except (OSError, ValueError):
            return AppSettings().normalized()
        if not isinstance(parsed, dict):
            return AppSettings().normalized()
        return _settings_from_mapping(parsed)

    def save(self, settings: AppSettings) -> AppSettings:
        """Persist *settings* atomically and return the normalized copy.

        The file is written to a temporary sibling and moved into place with
        :func:`os.replace`, so a crash mid-write cannot leave a truncated
        settings file behind.  Raises :class:`OSError` on a real write
        failure.
        """
        normalized = settings.normalized()
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

        descriptor, temporary = tempfile.mkstemp(
            dir=self._path.parent,
            prefix=f".{self._path.name}.",
            suffix=".tmp",
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
