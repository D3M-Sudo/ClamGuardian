from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path


class DatabaseStatus(StrEnum):
    AVAILABLE = "available"
    INSTALLED = "installed"
    DISABLED = "disabled"
    UPDATING = "updating"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class DatabaseArtifact:
    filename: str
    url: str
    sha256: str | None = None


@dataclass(frozen=True, slots=True)
class DatabaseSource:
    id: str
    name: str
    description: str
    artifacts: tuple[DatabaseArtifact, ...]
    enabled: bool = True
    auto_update: bool = True
    added_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self):
        if not self.id.strip() or not self.name.strip():
            raise ValueError("Database source id and name cannot be empty")
        if not self.artifacts:
            raise ValueError("Database source must contain at least one artifact")
        for a in self.artifacts:
            if Path(a.filename).name != a.filename:
                raise ValueError(f"Unsafe artifact filename: {a.filename!r}")
            if not a.url.startswith("https://"):
                raise ValueError("Database artifact URLs must use HTTPS")
            if a.sha256 is not None:
                digest = a.sha256.lower()
                if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                    raise ValueError(f"Invalid SHA-256 digest for {a.filename}")


@dataclass(frozen=True, slots=True)
class InstalledDatabase:
    source: DatabaseSource
    status: DatabaseStatus
    installed_at: datetime | None = None
    last_error: str | None = None
    artifact_files: tuple[str, ...] = ()
