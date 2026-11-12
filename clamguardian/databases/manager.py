from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import shutil
import tempfile
import threading
from _thread import LockType
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from .models import DatabaseArtifact, DatabaseSource, DatabaseStatus, InstalledDatabase
from .provider import DatabaseProvider, FileDatabaseProvider

logger = logging.getLogger(__name__)


class DatabaseUpdateError(RuntimeError):
    pass


StatusCallback = Callable[[InstalledDatabase], Awaitable[None] | None]


@asynccontextmanager
async def _async_thread_lock(lock: LockType) -> AsyncIterator[None]:
    """Acquire a process-wide lock without blocking or binding to one event loop."""
    acquired = False
    try:
        while not lock.acquire(blocking=False):
            await asyncio.sleep(0.01)
        acquired = True
        yield
    finally:
        if acquired:
            lock.release()


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
        self._locks: dict[str, LockType] = {}
        self._locks_guard = threading.Lock()
        self._state_lock = threading.RLock()
        self._updating_sources: set[str] = set()
        self._load_state()

    @property
    def sources(self):
        with self._state_lock:
            return tuple(self._sources.values())

    @property
    def installed(self):
        with self._state_lock:
            return tuple(self._installed.values())

    def add_source(self, source: DatabaseSource) -> None:
        with self._state_lock:
            if source.id in self._sources:
                raise ValueError(f"Database source already exists: {source.id}")
            self._ensure_artifact_names_available(source)
            self._sources[source.id] = source
            self._persist()

    def remove_source(self, source_id: str) -> None:
        with self._state_lock:
            if source_id in self._updating_sources:
                raise RuntimeError(
                    f"Cannot remove database source while its update is in progress: {source_id}"
                )
            source = self._require(source_id)
            remaining = [
                candidate for candidate_id, candidate in self._sources.items()
                if candidate_id != source_id
            ]
            for artifact in source.artifacts:
                if not any(
                    other.filename == artifact.filename
                    for candidate in remaining
                    for other in candidate.artifacts
                ):
                    (self.database_dir / artifact.filename).unlink(missing_ok=True)
            self._sources.pop(source_id)
            self._installed.pop(source_id, None)
            self._persist()

    def _ensure_artifact_names_available(
        self, source: DatabaseSource, *, excluding_source_id: str | None = None
    ) -> None:
        """Prevent sources from overwriting or deleting one another's artifacts."""
        wanted = {artifact.filename for artifact in source.artifacts}
        for existing_id, existing in self._sources.items():
            if existing_id == excluding_source_id:
                continue
            conflicts = wanted.intersection(
                artifact.filename for artifact in existing.artifacts
            )
            if conflicts:
                names = ", ".join(sorted(conflicts))
                raise ValueError(
                    f"Database artifact filename(s) already owned by "
                    f"source {existing_id!r}: {names}"
                )

    def set_enabled(self, source_id, enabled):
        with self._state_lock:
            if source_id in self._updating_sources:
                raise RuntimeError(
                    "Cannot change database source state while its update is in "
                    f"progress: {source_id}"
                )
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
        with self._state_lock:
            if source_id in self._updating_sources:
                raise RuntimeError(
                    f"Cannot change database source state while its update is in progress: {source_id}"
                )
            s = self._require(source_id)
            self._sources[source_id] = DatabaseSource(
                s.id, s.name, s.description, s.artifacts, s.enabled, enabled, s.added_at
            )
            self._persist()

    def status(self, source_id):
        with self._state_lock:
            s = self._require(source_id)
            return self._installed.get(
                source_id, InstalledDatabase(s, DatabaseStatus.AVAILABLE)
            )

    async def update(self, source_id: str) -> InstalledDatabase:
        with self._state_lock:
            source = self._require(source_id)
            if not source.enabled:
                raise DatabaseUpdateError(f"Database source is disabled: {source.name}")
        with self._locks_guard:
            lock = self._locks.setdefault(source_id, threading.Lock())

        async with _async_thread_lock(lock):
            with self._state_lock:
                source = self._require(source_id)
                if not source.enabled:
                    raise DatabaseUpdateError(
                        f"Database source is disabled: {source.name}"
                    )
                previous = self._installed.get(source_id)
                self._updating_sources.add(source_id)

            staging: Path | None = None
            backup: Path | None = None
            moved: list[tuple[Path, Path]] = []
            rollback_complete = False
            try:
                with self._state_lock:
                    self._ensure_artifact_names_available(
                        source, excluding_source_id=source_id
                    )
                # The parent may not exist on first run. Create it before using
                # it as the parent of the private staging and rollback dirs.
                self.database_dir.parent.mkdir(parents=True, exist_ok=True)
                staging = Path(
                    tempfile.mkdtemp(
                        prefix=".clamguardian-db-stage-",
                        dir=self.database_dir.parent,
                    )
                )
                backup = Path(
                    tempfile.mkdtemp(
                        prefix=".clamguardian-db-backup-",
                        dir=self.database_dir.parent,
                    )
                )
                self.database_dir.mkdir(parents=True, exist_ok=True)
                await self._emit(
                    InstalledDatabase(
                        source,
                        DatabaseStatus.UPDATING,
                        previous.installed_at if previous else None,
                    )
                )
                staged = [p async for p in self.provider.download(source, staging)]
                for path in staged:
                    destination = self.database_dir / path.name
                    backup_path = backup / path.name
                    if destination.exists():
                        destination.replace(backup_path)
                    # Record before installing so a failed move restores the
                    # previous artifact before the backup directory is removed.
                    moved.append((destination, backup_path))
                    path.replace(destination)
                result = InstalledDatabase(
                    source,
                    DatabaseStatus.INSTALLED,
                    datetime.now(UTC),
                    None,
                    tuple(a.filename for a in source.artifacts),
                )
                with self._state_lock:
                    self._installed[source_id] = result
                    self._persist()
                await self._emit(result)
                rollback_complete = True
                return result
            except asyncio.CancelledError:
                rollback_complete = self._rollback_moved(moved)
                with self._state_lock:
                    if rollback_complete:
                        if previous is None:
                            self._installed.pop(source_id, None)
                            restored_status = InstalledDatabase(
                                source, DatabaseStatus.AVAILABLE
                            )
                        else:
                            self._installed[source_id] = previous
                            restored_status = previous
                    else:
                        recovery_path = str(backup) if backup is not None else "unknown"
                        restored_status = InstalledDatabase(
                            source,
                            DatabaseStatus.ERROR,
                            previous.installed_at if previous else None,
                            "Cancelled update could not be fully rolled back; "
                            f"recovery data preserved at {recovery_path}",
                            previous.artifact_files if previous else (),
                        )
                        self._installed[source_id] = restored_status
                    try:
                        self._persist()
                    except Exception:
                        logger.exception(
                            "Could not persist database state after cancelled update"
                        )
                with contextlib.suppress(BaseException):
                    await self._emit(restored_status)
                raise
            except Exception as exc:
                rollback_complete = self._rollback_moved(moved)
                result = InstalledDatabase(
                    source,
                    DatabaseStatus.ERROR,
                    previous.installed_at if previous else None,
                    str(exc),
                    previous.artifact_files if previous else (),
                )
                with self._state_lock:
                    self._installed[source_id] = result
                    self._persist()
                await self._emit(result)
                raise DatabaseUpdateError(
                    f"Update failed for {source.name}: {exc}"
                ) from exc
            finally:
                if staging is not None:
                    shutil.rmtree(staging, ignore_errors=True)
                if backup is not None:
                    if rollback_complete:
                        shutil.rmtree(backup, ignore_errors=True)
                    else:
                        logger.error(
                            "Database rollback was incomplete; preserving recovery "
                            "artifacts at %s",
                            backup,
                        )
                with self._state_lock:
                    self._updating_sources.discard(source_id)

    @staticmethod
    def _rollback_moved(moved: list[tuple[Path, Path]]) -> bool:
        """Restore replaced artifacts; preserve backups if any rollback step fails."""
        complete = True
        for destination, backup_path in reversed(moved):
            try:
                destination.unlink(missing_ok=True)
                if backup_path.exists():
                    backup_path.replace(destination)
            except OSError:
                complete = False
                logger.exception(
                    "Could not roll back database artifact %s from %s",
                    destination,
                    backup_path,
                )
        return complete

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
        with self._state_lock:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "sources": [self._source_dict(s) for s in self._sources.values()],
                "installed": {
                    key: self._installed_dict(value)
                    for key, value in self._installed.items()
                },
            }
            fd, temp = tempfile.mkstemp(
                prefix=self.state_file.name + ".", dir=self.state_file.parent
            )
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
