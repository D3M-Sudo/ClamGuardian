from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from clamguardian.databases.manager import DatabaseManager, DatabaseUpdateError
from clamguardian.databases.models import DatabaseArtifact, DatabaseSource, DatabaseStatus


class FakeProvider:
    def __init__(self, content=b"good", fail=False):
        self.content, self.fail = content, fail

    async def download(self, source, destination):
        if self.fail:
            raise RuntimeError("network unavailable")
        destination.mkdir(parents=True, exist_ok=True)
        p = destination / source.artifacts[0].filename
        p.write_bytes(self.content)
        yield p


def source():
    digest = hashlib.sha256(b"good").hexdigest()
    return DatabaseSource(
        "thirdparty",
        "Third Party",
        "Test source",
        (DatabaseArtifact("thirdparty.cvd", "https://example.invalid/db.cvd", digest),),
    )


@pytest.mark.asyncio
async def test_add_update_and_persist(tmp_path: Path):
    m = DatabaseManager(tmp_path / "db", tmp_path / "state.json", provider=FakeProvider())
    m.add_source(source())
    r = await m.update("thirdparty")
    assert r.status == DatabaseStatus.INSTALLED
    assert (tmp_path / "db" / "thirdparty.cvd").read_bytes() == b"good"
    restored = DatabaseManager(tmp_path / "db", tmp_path / "state.json", provider=FakeProvider())
    assert restored.sources[0].name == "Third Party"
    assert restored.status("thirdparty").status == DatabaseStatus.INSTALLED


@pytest.mark.asyncio
async def test_failed_update_preserves_previous(tmp_path: Path):
    m = DatabaseManager(tmp_path / "db", tmp_path / "state.json", provider=FakeProvider(b"good"))
    m.add_source(source())
    await m.update("thirdparty")
    m.provider = FakeProvider(b"bad", fail=True)
    with pytest.raises(DatabaseUpdateError):
        await m.update("thirdparty")
    assert (tmp_path / "db" / "thirdparty.cvd").read_bytes() == b"good"
    assert m.status("thirdparty").status == DatabaseStatus.ERROR


def test_rejects_unsafe_source():
    with pytest.raises(ValueError):
        DatabaseSource(
            "x", "X", "x", (DatabaseArtifact("../evil.cvd", "https://example.invalid/x"),)
        )


# ---------------------------------------------------------------------------
# Phase 3 Security Gap Closure: Database Verifier & Provider
# ---------------------------------------------------------------------------


def test_verify_sha256_checksum_mismatch(tmp_path: Path):
    from clamguardian.databases.verifier import verify_sha256

    target = tmp_path / "test.db"
    target.write_bytes(b"actual content")
    wrong_hash = "0" * 64

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        verify_sha256(target, wrong_hash)


def test_verify_sha256_matching_checksum(tmp_path: Path):
    from clamguardian.databases.verifier import verify_sha256

    target = tmp_path / "test.db"
    data = b"matching content"
    target.write_bytes(data)
    correct_hash = hashlib.sha256(data).hexdigest()

    verify_sha256(target, correct_hash)  # no raise


# ---------------------------------------------------------------------------
# Phase 3 Security Gap Closure: provider-level digest enforcement
# ---------------------------------------------------------------------------


class _FakeResponse:
    """Minimal aiohttp response: only what FileDatabaseProvider consumes."""

    def __init__(self, payload: bytes) -> None:
        self._payload = payload
        self.content_length = len(payload)

    def raise_for_status(self) -> None:
        return None

    @property
    def content(self) -> _FakeResponse:
        return self

    async def iter_chunked(self, size: int):
        for start in range(0, len(self._payload), size):
            yield self._payload[start : start + size]

    async def __aenter__(self) -> _FakeResponse:
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        return False


class _FakeSession:
    """Stand-in for ``aiohttp.ClientSession`` that serves a fixed payload."""

    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        return False

    def get(self, url: str, allow_redirects: bool = True) -> _FakeResponse:
        return _FakeResponse(self._payload)


def _artifact_source(payload: bytes, digest: str):
    return DatabaseSource(
        "thirdparty",
        "Third Party",
        "Test source",
        (DatabaseArtifact("thirdparty.cvd", "https://example.invalid/db.cvd", digest),),
    )


@pytest.mark.asyncio
async def test_provider_installs_artifact_only_after_digest_verification(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """A verified download publishes the artifact and leaves no ``.part`` behind."""
    from clamguardian.databases import provider as provider_module
    from clamguardian.databases.provider import FileDatabaseProvider

    payload = b"verified definitions"
    provider = FileDatabaseProvider()
    monkeypatch.setattr(
        provider_module.aiohttp, "ClientSession", lambda *a, **k: _FakeSession(payload)
    )

    destination = tmp_path / "db"
    installed = [
        path
        async for path in provider.download(
            _artifact_source(payload, hashlib.sha256(payload).hexdigest()), destination
        )
    ]

    assert [p.name for p in installed] == ["thirdparty.cvd"]
    assert (destination / "thirdparty.cvd").read_bytes() == payload
    assert list(destination.glob("*.part")) == []


@pytest.mark.asyncio
async def test_provider_aborts_install_on_digest_mismatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """A tampered download must abort the install and publish nothing."""
    from clamguardian.databases import provider as provider_module
    from clamguardian.databases.provider import FileDatabaseProvider

    provider = FileDatabaseProvider()
    monkeypatch.setattr(
        provider_module.aiohttp,
        "ClientSession",
        lambda *a, **k: _FakeSession(b"tampered payload"),
    )

    destination = tmp_path / "db"
    source = _artifact_source(b"expected payload", hashlib.sha256(b"expected payload").hexdigest())

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        async for _ in provider.download(source, destination):
            pass

    assert list(destination.glob("*")) == []


@pytest.mark.asyncio
async def test_provider_refuses_artifact_without_digest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """M5 (P1-DB-01): an artifact with no declared digest must never be installed.

    Fail closed: without a digest the payload cannot be verified, so it must be
    refused *before* any byte is fetched, not installed and trusted.
    """
    from clamguardian.databases import provider as provider_module
    from clamguardian.databases.provider import FileDatabaseProvider

    provider = FileDatabaseProvider()
    monkeypatch.setattr(
        provider_module.aiohttp,
        "ClientSession",
        lambda *a, **k: _FakeSession(b"unverified payload"),
    )
    source = DatabaseSource(
        "thirdparty",
        "Third Party",
        "Test source",
        (DatabaseArtifact("thirdparty.cvd", "https://example.invalid/db.cvd"),),
    )

    destination = tmp_path / "db"
    with pytest.raises(ValueError, match="no SHA-256 digest"):
        async for _ in provider.download(source, destination):
            pass

    assert list(destination.glob("*")) == []


@pytest.mark.asyncio
async def test_manager_update_refuses_digestless_artifact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """M5 (P1-DB-01): the refusal is surfaced as a failed update, nothing installed."""
    from clamguardian.databases import provider as provider_module
    from clamguardian.databases.provider import FileDatabaseProvider

    monkeypatch.setattr(
        provider_module.aiohttp,
        "ClientSession",
        lambda *a, **k: _FakeSession(b"unverified payload"),
    )
    manager = DatabaseManager(
        tmp_path / "db", tmp_path / "state.json", provider=FileDatabaseProvider()
    )
    manager.add_source(
        DatabaseSource(
            "thirdparty",
            "Third Party",
            "Test source",
            (DatabaseArtifact("thirdparty.cvd", "https://example.invalid/db.cvd"),),
        )
    )

    with pytest.raises(DatabaseUpdateError, match="no SHA-256 digest"):
        await manager.update("thirdparty")

    assert not (tmp_path / "db" / "thirdparty.cvd").exists()
    assert manager.status("thirdparty").status == DatabaseStatus.ERROR


class SelectiveProvider:
    """Serves a fixed payload per source and can fail for one specific source."""

    def __init__(self, fail_for: str = "") -> None:
        self.fail_for = fail_for

    async def download(self, source, destination):
        if source.id == self.fail_for:
            raise RuntimeError("network unavailable")
        destination.mkdir(parents=True, exist_ok=True)
        payload = b"good"
        path = destination / source.artifacts[0].filename
        path.write_bytes(payload)
        yield path


def _named_source(source_id: str, *, enabled: bool = True, auto_update: bool = True):
    digest = hashlib.sha256(b"good").hexdigest()
    return DatabaseSource(
        source_id,
        source_id.title(),
        "Test source",
        (DatabaseArtifact(f"{source_id}.cvd", "https://example.invalid/db.cvd", digest),),
        enabled,
        auto_update,
    )


@pytest.mark.asyncio
async def test_rollback_restores_previous_artifact_when_install_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """M5 (P3-DBG-03): a failure while installing must not lose the old database.

    The original artifact is moved to a backup directory that is deleted in the
    ``finally`` block, so the rollback entry has to be recorded *before* the
    staged file is moved into place.
    """
    database_dir = tmp_path / "db"
    manager = DatabaseManager(
        database_dir, tmp_path / "state.json", provider=SelectiveProvider()
    )
    manager.add_source(_named_source("thirdparty"))
    await manager.update("thirdparty")
    assert (database_dir / "thirdparty.cvd").read_bytes() == b"good"

    real_replace = Path.replace

    def failing_replace(self: Path, target: Path) -> Path:
        # Fail only the install move (staging dir -> database dir): the rollback
        # restore (backup dir -> database dir) must be allowed to succeed.
        source_dir = self.parent.name
        if (
            Path(target).parent == database_dir
            and source_dir.startswith(".thirdparty-")
            and "-backup-" not in source_dir
        ):
            raise OSError("simulated install failure")
        return real_replace(self, target)

    monkeypatch.setattr(Path, "replace", failing_replace)

    with pytest.raises(DatabaseUpdateError):
        await manager.update("thirdparty")

    assert (database_dir / "thirdparty.cvd").read_bytes() == b"good"


@pytest.mark.asyncio
async def test_update_enabled_updates_eligible_sources_and_isolates_failures(
    tmp_path: Path,
):
    """'Update all' updates every eligible source and survives a failing one."""
    manager = DatabaseManager(
        tmp_path / "db", tmp_path / "state.json", provider=SelectiveProvider(fail_for="broken")
    )
    manager.add_source(_named_source("ok"))
    manager.add_source(_named_source("manual", auto_update=False))
    manager.add_source(_named_source("broken"))
    manager.add_source(_named_source("disabled", enabled=False))

    results = await manager.update_enabled()

    assert sorted(entry.source.id for entry in results) == ["broken", "ok"]
    assert manager.status("ok").status == DatabaseStatus.INSTALLED
    assert manager.status("broken").status == DatabaseStatus.ERROR
