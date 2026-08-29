from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
from collections.abc import Awaitable, Callable
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from .models import DatabaseArtifact, DatabaseSource, DatabaseStatus, InstalledDatabase
from .provider import DatabaseProvider, FileDatabaseProvider


class DatabaseUpdateError(RuntimeError):
    pass


StatusCallback = Callable[[InstalledDatabase], Awaitable[None] | None]


class DatabaseManager:
    """Persistent ClamUI-inspired manager with atomic install and rollback."""

    def __init__(
        self,
        database_dir: Path,
        state_file: Path,
        *,
        provider: DatabaseProvider | None = None,
        status_callback: StatusCallback | None = None,
    ):
        self.database_dir = Path(database_dir)
        self.state_file = Path(state_file)
        self.provider = provider or FileDatabaseProvider()
        self.status_callback = status_callback
        self._sources: dict[str, DatabaseSource] = {}
        self._installed: dict[str, InstalledDatabase] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._load_state()

    @property
    def sources(self):
        return tuple(self._sources.values())

    @property
    def installed(self):
        return tuple(self._installed.values())

    def add_source(self, source):
        if source.id in self._sources:
            raise ValueError(f"Database source already exists: {source.id}")
        self._sources[source.id] = source
        self._persist()

    def remove_source(self, source_id):
        source = self._require(source_id)
        for artifact in source.artifacts:
            (self.database_dir / artifact.filename).unlink(missing_ok=True)
        self._sources.pop(source_id)
        self._installed.pop(source_id, None)
        self._persist()

    def set_enabled(self, source_id, enabled):
        s = self._require(source_id)
        self._sources[source_id] = DatabaseSource(
            s.id, s.name, s.description, s.artifacts, enabled, s.auto_update, s.added_at
        )
        current = self._installed.get(source_id)
        if current:
            self._installed[source_id] = InstalledDatabase(
                self._sources[source_id],
                DatabaseStatus.INSTALLED if enabled else DatabaseStatus.DISABLED,
                current.installed_at,
                current.last_error,
                current.artifact_files,
            )
        self._persist()

    def set_auto_update(self, source_id, enabled):
        s = self._require(source_id)
        self._sources[source_id] = DatabaseSource(
            s.id, s.name, s.description, s.artifacts, s.enabled, enabled, s.added_at
        )
        self._persist()

    def status(self, source_id):
        s = self._require(source_id)
        return self._installed.get(source_id, InstalledDatabase(s, DatabaseStatus.AVAILABLE))

    async def update(self, source_id):
        source = self._require(source_id)
        if not source.enabled:
            raise DatabaseUpdateError(f"Database source is disabled: {source.name}")
        lock = self._locks.setdefault(source_id, asyncio.Lock())
        async with lock:
            previous = self._installed.get(source_id)
            staging = Path(tempfile.mkdtemp(prefix=f".{source.id}-", dir=self.database_dir.parent))
            backup = Path(
                tempfile.mkdtemp(prefix=f".{source.id}-backup-", dir=self.database_dir.parent)
            )
            try:
                self.database_dir.mkdir(parents=True, exist_ok=True)
                await self._emit(
                    InstalledDatabase(
                        source, DatabaseStatus.UPDATING, previous.installed_at if previous else None
                    )
                )
                staged = [p async for p in self.provider.download(source, staging)]
                moved = []
                for path in staged:
                    destination = self.database_dir / path.name
                    backup_path = backup / path.name
                    if destination.exists():
                        destination.replace(backup_path)
                    path.replace(destination)
                    moved.append((destination, backup_path))
                result = InstalledDatabase(
                    source,
                    DatabaseStatus.INSTALLED,
                    datetime.now(UTC),
                    None,
                    tuple(a.filename for a in source.artifacts),
                )
                self._installed[source_id] = result
                self._persist()
                await self._emit(result)
                return result
            except Exception as exc:
                moved = locals().get("moved", [])
                for destination, backup_path in moved:
                    destination.unlink(missing_ok=True)
                    if backup_path.exists():
                        backup_path.replace(destination)
                result = InstalledDatabase(
                    source,
                    DatabaseStatus.ERROR,
                    previous.installed_at if previous else None,
                    str(exc),
                    previous.artifact_files if previous else (),
                )
                self._installed[source_id] = result
                self._persist()
                await self._emit(result)
                raise DatabaseUpdateError(f"Update failed for {source.name}: {exc}") from exc
            finally:
                shutil.rmtree(staging, ignore_errors=True)
                shutil.rmtree(backup, ignore_errors=True)

    async def update_enabled(self):
        results = []
        for source in self.sources:
            if source.enabled and source.auto_update:
                try:
                    results.append(await self.update(source.id))
                except DatabaseUpdateError:
                    results.append(self.status(source.id))
        return tuple(results)

    async def _emit(self, status):
        if self.status_callback:
            result = self.status_callback(status)
            if asyncio.iscoroutine(result):
                await result

    def _require(self, source_id):
        if source_id not in self._sources:
            raise KeyError(f"Unknown database source: {source_id}")
        return self._sources[source_id]

    def _persist(self):
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "sources": [self._source_dict(s) for s in self.sources],
            "installed": {k: self._installed_dict(v) for k, v in self._installed.items()},
        }
        fd, temp = tempfile.mkstemp(prefix=self.state_file.name + ".", dir=self.state_file.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
            os.replace(temp, self.state_file)
        finally:
            Path(temp).unlink(missing_ok=True)

    def _load_state(self):
        if not self.state_file.exists():
            return
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            for raw in data.get("sources", []):
                artifacts = tuple(DatabaseArtifact(**a) for a in raw["artifacts"])
                source = DatabaseSource(
                    raw["id"],
                    raw["name"],
                    raw["description"],
                    artifacts,
                    raw.get("enabled", True),
                    raw.get("auto_update", True),
                    datetime.fromisoformat(raw["added_at"]),
                )
                self._sources[source.id] = source
            for key, raw in data.get("installed", {}).items():
                if key in self._sources:
                    self._installed[key] = InstalledDatabase(
                        self._sources[key],
                        DatabaseStatus(raw["status"]),
                        datetime.fromisoformat(raw["installed_at"])
                        if raw.get("installed_at")
                        else None,
                        raw.get("last_error"),
                        tuple(raw.get("artifact_files", [])),
                    )
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Cannot load database manager state: {self.state_file}") from exc

    @staticmethod
    def _source_dict(source):
        data = asdict(source)
        data["added_at"] = source.added_at.isoformat()
        return data

    @staticmethod
    def _installed_dict(installed):
        return {
            "status": installed.status.value,
            "installed_at": installed.installed_at.isoformat() if installed.installed_at else None,
            "last_error": installed.last_error,
            "artifact_files": list(installed.artifact_files),
        }
