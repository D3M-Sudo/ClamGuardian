from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from pathlib import Path

import aiohttp

from .models import DatabaseSource
from .verifier import verify_sha256


class DatabaseProvider(ABC):
    @abstractmethod
    async def download(self, source: DatabaseSource, destination: Path) -> AsyncIterator[Path]:
        raise NotImplementedError


class FileDatabaseProvider(DatabaseProvider):
    def __init__(self, timeout_seconds: float = 120.0, max_artifact_bytes: int = 512 * 1024 * 1024):
        self.timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        self.max_artifact_bytes = max_artifact_bytes

    async def download(self, source, destination):
        destination.mkdir(parents=True, exist_ok=True)
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            for artifact in source.artifacts:
                output = destination / artifact.filename
                temporary = output.with_name(output.name + ".part")
                try:
                    async with session.get(artifact.url, allow_redirects=True) as response:
                        response.raise_for_status()
                        if (
                            response.content_length
                            and response.content_length > self.max_artifact_bytes
                        ):
                            raise ValueError(f"Artifact {artifact.filename} exceeds size limit")
                        written = 0
                        with temporary.open("wb") as handle:
                            async for chunk in response.content.iter_chunked(1024 * 1024):
                                written += len(chunk)
                                if written > self.max_artifact_bytes:
                                    raise ValueError(
                                        f"Artifact {artifact.filename} exceeds size limit"
                                    )
                                handle.write(chunk)
                    if artifact.sha256:
                        verify_sha256(temporary, artifact.sha256)
                    temporary.replace(output)
                    yield output
                except Exception:
                    temporary.unlink(missing_ok=True)
                    raise
