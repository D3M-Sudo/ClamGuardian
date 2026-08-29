"""Core interfaces and immutable scan result types."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Normalized result returned by every AV engine implementation."""

    target: str
    clean: bool
    threats: tuple[str, ...] = ()
    engine: str = "unknown"
    error: str | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def duration_seconds(self) -> float:
        """Return elapsed scan time in seconds."""
        return max(0.0, (self.finished_at - self.started_at).total_seconds())


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
