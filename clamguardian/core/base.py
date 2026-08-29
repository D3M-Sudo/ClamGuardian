"""Core interfaces and immutable scan result types."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any


class ScanStatus(Enum):
    """Terminal states of a scan, mutually exclusive by construction.

    ``CANCELLED`` is semantically distinct from ``ERROR`` and ``TIMEOUT``:
    cancellation is requested by the caller, never a failure of the engine.
    """

    CLEAN = "clean"
    INFECTED = "infected"
    ERROR = "error"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class ScanProgress:
    """Immutable snapshot of in-flight scan progress.

    ``percent`` is optional: neither clamd nor ``clamscan`` provide reliable
    percentage information, so consumers must treat it as absent unless the
    engine can genuinely compute it. ``phase`` is a free-form label chosen by
    the engine (e.g. ``"initializing"``, ``"scanning"``, ``"finalizing"``).
    """

    phase: str = "scanning"
    files_scanned: int = 0
    bytes_scanned: int = 0
    current_path: str | None = None
    threats_found: int = 0
    elapsed_seconds: float = 0.0
    percent: float | None = None


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Normalized result returned by every AV engine implementation.

    ``status`` is the authoritative terminal state. The legacy ``clean``
    boolean is kept for backward compatibility and is always consistent with
    ``status`` (``clean`` is ``True`` only for :attr:`ScanStatus.CLEAN`).
    """

    target: str
    clean: bool
    status: ScanStatus = ScanStatus.CLEAN
    threats: tuple[str, ...] = ()
    files_scanned: int = 0
    engine: str = "unknown"
    error: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if self.status is ScanStatus.CLEAN and (self.threats or self.error):
            # Keep status consistent with the payload when the caller only
            # passed the legacy ``clean`` boolean.
            object.__setattr__(
                self,
                "status",
                ScanStatus.INFECTED if self.threats else ScanStatus.ERROR,
            )
        object.__setattr__(self, "clean", self.status is ScanStatus.CLEAN)

    @property
    def duration_seconds(self) -> float:
        """Return elapsed scan time in seconds."""
        return max(0.0, (self.finished_at - self.started_at).total_seconds())

    @classmethod
    def cancelled(cls, target: str, started_at: datetime | None = None) -> ScanResult:
        """Build a result representing a caller-requested cancellation."""
        return cls(
            target=target,
            clean=False,
            status=ScanStatus.CANCELLED,
            started_at=started_at or datetime.now(UTC),
        )

    @classmethod
    def timed_out(cls, target: str, started_at: datetime | None = None) -> ScanResult:
        """Build a result representing an engine-level timeout."""
        return cls(
            target=target,
            clean=False,
            status=ScanStatus.TIMEOUT,
            error="scan timed out",
            started_at=started_at or datetime.now(UTC),
        )


class BaseAVEngine(ABC):
    """Abstract asynchronous antivirus engine contract."""

    name: str

    @abstractmethod
    async def scan(self, target: Path, *, recursive: bool = True) -> ScanResult:
        """Scan a file or directory and return a normalized result."""
        raise NotImplementedError

    @abstractmethod
    async def update_signatures(self) -> str:
        """Update antivirus signatures and return human-readable output."""
        raise NotImplementedError


class BaseThreatProvider(ABC):
    """Interface implemented by dynamic threat-intelligence providers."""

    name: str

    @abstractmethod
    async def lookup_hash(self, sha256: str) -> dict[str, Any]:
        """Look up a SHA-256 digest and return normalized provider data."""
        raise NotImplementedError
