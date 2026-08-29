"""Immutable scan profiles: UI-agnostic scan configuration.

A :class:`ScanProfile` is a validated, immutable bundle of *semantic* scan
options (recursion, archives, mail, size limits...). It deliberately knows
nothing about ClamAV, subprocesses, GTK or the CLI: the translation to
engine-specific configuration lives in the engine layer
(:mod:`clamguardian.engines.clamav`), so that GTK, future CLI and headless
front-ends all share the same Core API.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace

from .errors import ProfileError

__all__ = ["ScanProfile", "ScanProfileRegistry", "DEFAULT_PROFILE", "DEFAULT_REGISTRY"]


@dataclass(frozen=True, slots=True)
class ScanProfile:
    """Immutable, validated description of *how* a scan must be performed.

    Only options with concrete value for ClamGuardian 1.0 are exposed; raw
    ClamAV flags must never leak into front-ends.
    """

    id: str
    name: str
    description: str = ""
    recursive: bool = True
    scan_archives: bool = True
    scan_mail: bool = True
    detect_pua: bool = False
    max_filesize_mib: int | None = None
    max_scansize_mib: int | None = None
    max_recursion: int | None = None
    max_files: int | None = None
    follow_symlinks: bool | None = None

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        """Raise :class:`ProfileError` if the profile is not usable."""
        if not self.id or not self.id.strip():
            raise ProfileError("profile id must be a non-empty string")
        if not self.name or not self.name.strip():
            raise ProfileError(f"profile {self.id!r}: name must be a non-empty string")
        for field_name in ("max_filesize_mib", "max_scansize_mib"):
            value = getattr(self, field_name)
            if value is not None and value <= 0:
                raise ProfileError(f"profile {self.id!r}: {field_name} must be positive")
        for field_name in ("max_recursion", "max_files"):
            value = getattr(self, field_name)
            if value is not None and value < 1:
                raise ProfileError(f"profile {self.id!r}: {field_name} must be >= 1")
        if (
            self.max_filesize_mib is not None
            and self.max_scansize_mib is not None
            and self.max_scansize_mib < self.max_filesize_mib
        ):
            raise ProfileError(
                f"profile {self.id!r}: max_scansize_mib ({self.max_scansize_mib}) "
                f"cannot be smaller than max_filesize_mib ({self.max_filesize_mib})"
            )

    def with_overrides(self, **overrides: object) -> ScanProfile:
        """Return a new validated profile derived from this one."""
        return replace(self, **overrides)  # type: ignore[arg-type]

    # -- Built-in presets ---------------------------------------------------

    @classmethod
    def quick(cls) -> ScanProfile:
        """Fast scan of high-relevance areas: bounded depth and sizes."""
        return cls(
            id="quick",
            name="Quick Scan",
            description="Fast scan with bounded archive depth and size limits.",
            scan_mail=False,
            max_filesize_mib=25,
            max_scansize_mib=100,
            max_recursion=8,
        )

    @classmethod
    def home(cls) -> ScanProfile:
        """Thorough scan of the user's home directory."""
        return cls(
            id="home",
            name="Home Scan",
            description="Full-featured scan of the user's home directory.",
        )

    @classmethod
    def full(cls) -> ScanProfile:
        """Exhaustive scan of the provided target: no artificial limits."""
        return cls(
            id="full",
            name="Full Scan",
            description="Exhaustive scan: archives, mail, PUA, no size limits.",
            detect_pua=True,
        )

    @classmethod
    def custom(cls) -> ScanProfile:
        """Base profile the user can derive from via :meth:`with_overrides`."""
        return cls(id="custom", name="Custom Scan", description="User-configurable scan profile.")


#: Backward-compatible default: matches the pre-M2 engine behaviour
#: (recursion on, everything else left to engine defaults).
DEFAULT_PROFILE = ScanProfile(id="default", name="Standard Scan")


class ScanProfileRegistry:
    """Registry/factory of :class:`ScanProfile` instances keyed by id."""

    def __init__(self, profiles: Iterable[ScanProfile] = ()) -> None:
        self._profiles: dict[str, ScanProfile] = {}
        for profile in profiles:
            self.register(profile)

    def register(self, profile: ScanProfile) -> None:
        """Validate and register *profile* (re-registering an id replaces it)."""
        profile.validate()
        self._profiles[profile.id] = profile

    def get(self, profile_id: str) -> ScanProfile:
        """Return the profile registered under *profile_id*.

        Raises :class:`ProfileError` for unknown ids.
        """
        try:
            return self._profiles[profile_id]
        except KeyError:
            known = ", ".join(sorted(self._profiles)) or "<none>"
            raise ProfileError(f"unknown scan profile {profile_id!r} (known: {known})") from None

    def list(self) -> tuple[ScanProfile, ...]:
        """All registered profiles, ordered by id."""
        return tuple(self._profiles[key] for key in sorted(self._profiles))

    def __contains__(self, profile_id: object) -> bool:
        return profile_id in self._profiles


#: Default registry with the four M2 presets.
DEFAULT_REGISTRY = ScanProfileRegistry(
    [ScanProfile.quick(), ScanProfile.home(), ScanProfile.full(), ScanProfile.custom()]
)
