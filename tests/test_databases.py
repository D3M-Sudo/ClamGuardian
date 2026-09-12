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
