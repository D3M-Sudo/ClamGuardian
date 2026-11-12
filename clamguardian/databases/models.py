from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlsplit


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
        if not isinstance(self.id, str) or not self.id.strip():
            raise ValueError("Database source id cannot be empty")
        if (
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", self.id) is None
            or ".." in self.id
        ):
            raise ValueError("Database source id must be a safe 1-64 character identifier")
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("Database source name cannot be empty")
        if not self.artifacts:
            raise ValueError("Database source must contain at least one artifact")

        filenames: set[str] = set()
        for artifact in self.artifacts:
            filename = artifact.filename
            if (
                not isinstance(filename, str)
                or not filename
                or filename in {".", ".."}
                or Path(filename).name != filename
                or "/" in filename
                or "\\" in filename
                or "\x00" in filename
            ):
                raise ValueError(f"Unsafe artifact filename: {filename!r}")
            if filename in filenames:
                raise ValueError(f"Duplicate artifact filename: {filename!r}")
            filenames.add(filename)

            if not isinstance(artifact.url, str):
                raise ValueError("Database artifact URLs must use HTTPS")
            parsed_url = urlsplit(artifact.url)
            if parsed_url.scheme != "https" or not parsed_url.hostname:
                raise ValueError("Database artifact URLs must use HTTPS and include a host")
            if artifact.sha256 is not None:
                if not isinstance(artifact.sha256, str):
                    raise ValueError(f"Invalid SHA-256 digest for {filename}")
                digest = artifact.sha256.lower()
                if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                    raise ValueError(f"Invalid SHA-256 digest for {filename}")


@dataclass(frozen=True, slots=True)
class InstalledDatabase:
    source: DatabaseSource
    status: DatabaseStatus
    installed_at: datetime | None = None
    last_error: str | None = None
    artifact_files: tuple[str, ...] = ()
