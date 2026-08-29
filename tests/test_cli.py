"""Tests for the ClamGuardian CLI (M3).

The suite uses fake engines and the injectable ``run()`` streams so no test
depends on a real ClamAV installation. The integration tests drive
CLI → ScanProfileRegistry → ScanTaskRunner → fake engine → ScanResult →
output, guaranteeing the CLI never grows its own scanning logic.
"""

from __future__ import annotations

import asyncio
import io
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from clamguardian.cli import main as cli_main
from clamguardian.cli import run
from clamguardian.core.base import BaseAVEngine, ScanResult, ScanStatus
from clamguardian.core.errors import EngineError
from clamguardian.core.profiles import ScanProfile
from clamguardian.core.runner import ScanTaskRunner
from clamguardian.history import history_record_from_scan
from clamguardian.history.interface import HistoryError, HistoryRecord, HistoryStore

# ---------------------------------------------------------------------------
# Fake engines and harness
# ---------------------------------------------------------------------------


class FakeEngine(BaseAVEngine):
    """Configurable fake engine: returns a canned result without subprocesses."""

    name = "fake"

    def __init__(self, result: ScanResult | None = None, exc: Exception | None = None):
        self.result = result
        self.exc = exc
        self.last_profile: ScanProfile | None = None
        self.last_target: Path | None = None

    async def scan(
        self, target: Path, *, recursive: bool = True, profile: ScanProfile | None = None
    ) -> ScanResult:
        self.last_target = target
        self.last_profile = profile
        if self.exc is not None:
            raise self.exc
        assert self.result is not None
        return self.result

    async def update_signatures(self) -> str:  # pragma: no cover - unused by CLI
        raise EngineError("not implemented")


def make_result(
    status: ScanStatus,
    *,
    target: str = "/tmp/target",
    threats: tuple[str, ...] = (),
    error: str | None = None,
    engine: str = "fake",
    files_scanned: int = 0,
) -> ScanResult:
    started = datetime.now(UTC) - timedelta(seconds=1)
    return ScanResult(
        target=target,
        clean=status is ScanStatus.CLEAN,
        status=status,
        threats=threats,
        files_scanned=files_scanned,
        engine=engine,
        error=error,
        started_at=started,
        finished_at=datetime.now(UTC),
    )


class FakeRecorder:
    """In-memory History store fake supporting both recording and querying.

    It stands in for the whole :class:`HistoryStore` protocol: ``record_scan``
    appends the raw :class:`ScanResult` to ``records`` (so the existing scan-flow
    assertions keep working) **and** persists a snapshot ``HistoryRecord`` that
    ``list_scans``/``get_scan`` serve back. ``close`` is recorded too.
    """

    def __init__(self, exc: Exception | None = None):
        self.exc = exc
        self.records: list[ScanResult] = []
        self.closed = False
        self._stored: dict[str, HistoryRecord] = {}

    async def record_scan(self, result: ScanResult) -> None:
        if self.exc is not None:
            raise self.exc
        self.records.append(result)
        record = history_record_from_scan(result)
        self._stored[record.id] = record

    async def get_scan(self, scan_id: str) -> HistoryRecord | None:
        if self.exc is not None:
            raise self.exc
        return self._stored.get(scan_id)

    async def list_scans(
        self,
        *,
        status: str | None = None,
        profile_id: str | None = None,
        since: object = None,
        until: object = None,
        limit: int = 100,
        offset: int = 0,
        ascending: bool = False,
    ) -> list[HistoryRecord]:
        if self.exc is not None:
            raise self.exc
        records = [r for r in self._stored.values() if status is None or r.status == status]
        records.sort(key=lambda r: r.started_at, reverse=not ascending)
        return records[offset : offset + limit]

    async def delete_scan(self, scan_id: str) -> bool:
        return self._stored.pop(scan_id, None) is not None

    async def clear_history(self) -> int:
        count = len(self._stored)
        self._stored.clear()
        return count

    async def purge(
        self,
        *,
        before: datetime | None = None,
        status: str | None = None,
    ) -> int:
        if before is None and status is None:
            raise ValueError("purge requires at least one of: before, status")
        to_delete: list[str] = []
        for rid, record in self._stored.items():
            if before is not None and record.started_at >= before:
                continue
            if status is not None and record.status != status:
                continue
            to_delete.append(rid)
        for rid in to_delete:
            del self._stored[rid]
        return len(to_delete)

    async def count_scans(self, *, status: str | None = None) -> int:
        return len(
            [r for r in self._stored.values() if status is None or r.status == status]
        )

    async def close(self) -> None:
        self.closed = True


class CLI:
    """Small harness capturing run() output and injecting a fake engine.

    A fake recorder is injected too so scan tests never touch a real history
    database; the recorder is exposed as ``harness.recorder`` for assertions.
    """

    def __init__(
        self,
        engine: BaseAVEngine,
        monkeypatch: pytest.MonkeyPatch,
        recorder: FakeRecorder | None = None,
    ):
        self.out = io.StringIO()
        self.err = io.StringIO()
        self.recorder = recorder if recorder is not None else FakeRecorder()
        monkeypatch.setattr(cli_main, "_default_engine", lambda: engine)
        monkeypatch.setattr(cli_main, "_default_history_store", lambda: self.recorder)

    def __call__(self, *argv: str) -> int:
        self.out.seek(0)
        self.out.truncate()
        self.err.seek(0)
        self.err.truncate()
        return run(list(argv), out=self.out, err=self.err)


@pytest.fixture
def cli(monkeypatch: pytest.MonkeyPatch):
    def factory(engine: BaseAVEngine, recorder: FakeRecorder | None = None) -> CLI:
        return CLI(engine, monkeypatch, recorder=recorder)

    return factory


# ---------------------------------------------------------------------------
# Help / version / profiles
# ---------------------------------------------------------------------------


def test_top_level_help(cli):
    harness = cli(FakeEngine())
    with pytest.raises(SystemExit) as excinfo:
        run(["--help"], out=harness.out, err=harness.err)
    assert excinfo.value.code == 0
    text = harness.out.getvalue()
    for word in ("scan", "profiles", "version", "Exit codes"):
        assert word in text


def test_scan_help_documents_profiles_and_json():
    out, err = io.StringIO(), io.StringIO()
    with pytest.raises(SystemExit) as excinfo:
        run(["scan", "--help"], out=out, err=err)
    assert excinfo.value.code == 0
    for word in ("--profile", "--json", "registry"):
        assert word in out.getvalue()


def test_version_command():
    out, err = io.StringIO(), io.StringIO()
    assert run(["version"], out=out, err=err) == 0
    assert "ClamGuardian" in out.getvalue()


def test_version_flag():
    out, err = io.StringIO(), io.StringIO()
    with pytest.raises(SystemExit) as excinfo:
        run(["--version"], out=out, err=err)
    assert excinfo.value.code == 0
    assert "ClamGuardian" in out.getvalue()


def test_profiles_command_uses_registry():
    out, err = io.StringIO(), io.StringIO()
    assert run(["profiles"], out=out, err=err) == 0
    text = out.getvalue()
    for profile_id in ("quick", "home", "full", "custom"):
        assert profile_id in text


def test_profiles_command_json():
    out, err = io.StringIO(), io.StringIO()
    assert run(["profiles", "--json"], out=out, err=err) == 0
    payload = json.loads(out.getvalue())
    assert [p["id"] for p in payload] == ["custom", "full", "home", "quick"]
    assert all({"id", "name", "description"} == set(p) for p in payload)


# ---------------------------------------------------------------------------
# Usage errors
# ---------------------------------------------------------------------------


def test_missing_command_is_usage_error():
    out, err = io.StringIO(), io.StringIO()
    with pytest.raises(SystemExit) as excinfo:
        run([], out=out, err=err)
    assert excinfo.value.code == 2


def test_unknown_profile_is_usage_error(tmp_path, cli):
    harness = cli(FakeEngine())
    assert harness("scan", str(tmp_path), "--profile", "nope") == 2
    assert "unknown scan profile" in harness.err.getvalue()


def test_missing_target_file(cli):
    harness = cli(FakeEngine())
    assert harness("scan", "/nonexistent/path/for/clamguardian") == 3
    assert "does not exist" in harness.err.getvalue()


# ---------------------------------------------------------------------------
# scan: exit code mapping via CLI → Runner → fake engine
# ---------------------------------------------------------------------------


def test_scan_clean_file(tmp_path, cli):
    target = tmp_path / "clean.txt"
    target.write_text("hello")
    engine = FakeEngine(make_result(ScanStatus.CLEAN, target=str(target)))
    harness = cli(engine)
    assert harness("scan", str(target)) == 0
    assert engine.last_profile is not None
    assert engine.last_profile.id == "default"  # Core DEFAULT_PROFILE
    assert "Status: CLEAN" in harness.out.getvalue()
    assert "Scanning..." in harness.out.getvalue()


def test_scan_selects_profile_from_registry(tmp_path, cli):
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    engine = FakeEngine(make_result(ScanStatus.CLEAN, target=str(target)))
    harness = cli(engine)
    assert harness("scan", str(target), "--profile", "quick") == 0
    assert engine.last_profile is not None
    assert engine.last_profile.id == "quick"
    assert "Profile: Quick Scan" in harness.out.getvalue()


def test_scan_infected_exit_code(tmp_path, cli):
    target = tmp_path / "evil.exe"
    target.write_bytes(b"x")
    engine = FakeEngine(
        make_result(ScanStatus.INFECTED, target=str(target), threats=("Eicar-Test-Signature",))
    )
    harness = cli(engine)
    assert harness("scan", str(target)) == 1
    assert "Eicar-Test-Signature" in harness.out.getvalue()


def test_scan_engine_error_exit_code(tmp_path, cli):
    target = tmp_path / "f"
    target.write_text("x")
    engine = FakeEngine(exc=EngineError("clamscan not found"))
    harness = cli(engine)
    assert harness("scan", str(target)) == 3
    assert "engine failure" in harness.err.getvalue()


def test_scan_timeout_exit_code(tmp_path, cli):
    target = tmp_path / "f"
    target.write_text("x")
    engine = FakeEngine(make_result(ScanStatus.TIMEOUT, error="scan timed out"))
    harness = cli(engine)
    assert harness("scan", str(target)) == 4


def test_scan_directory_target(tmp_path, cli):
    (tmp_path / "sub").mkdir()
    engine = FakeEngine(make_result(ScanStatus.CLEAN, target=str(tmp_path)))
    harness = cli(engine)
    assert harness("scan", str(tmp_path)) == 0


# ---------------------------------------------------------------------------
# JSON output contract
# ---------------------------------------------------------------------------


def test_scan_json_clean(tmp_path, cli):
    target = tmp_path / "f"
    target.write_text("x")
    engine = FakeEngine(
        make_result(ScanStatus.CLEAN, target=str(target), files_scanned=7, engine="clamscan")
    )
    harness = cli(engine)
    assert harness("scan", str(target), "--json") == 0
    payload = json.loads(harness.out.getvalue())
    assert list(payload) == [
        "status",
        "profile",
        "target",
        "engine",
        "threats",
        "files_scanned",
        "duration_seconds",
        "error",
        "metadata",
    ]
    assert payload["status"] == "clean"
    assert payload["profile"] == "default"
    assert payload["engine"] == "clamscan"
    assert payload["threats"] == []
    assert payload["files_scanned"] == 7
    assert payload["error"] is None


def test_scan_json_infected(tmp_path, cli):
    target = tmp_path / "f"
    target.write_text("x")
    engine = FakeEngine(
        make_result(ScanStatus.INFECTED, target=str(target), threats=("Sig",), files_scanned=3)
    )
    harness = cli(engine)
    assert harness("scan", str(target), "--profile", "full", "--json") == 1
    stdout = harness.out.getvalue()
    payload = json.loads(stdout)
    assert payload["status"] == "infected"
    assert payload["profile"] == "full"
    assert payload["threats"] == ["Sig"]
    # Exactly one line on stdout in JSON mode: no human noise.
    assert stdout.count("\n") == 1


def test_json_is_deterministic(tmp_path, cli):
    target = tmp_path / "f"
    target.write_text("x")
    result = make_result(ScanStatus.CLEAN, target=str(target), files_scanned=1)
    harness = cli(FakeEngine(result))
    assert harness("scan", str(target), "--json") == 0
    first = harness.out.getvalue()
    assert harness("scan", str(target), "--json") == 0
    assert harness.out.getvalue() == first


# ---------------------------------------------------------------------------
# Cancellation
# ---------------------------------------------------------------------------


def test_cancelled_scan_maps_to_exit_5(tmp_path, monkeypatch):
    target = tmp_path / "f"
    target.write_text("x")

    class CancellingRunner(ScanTaskRunner):
        async def submit(self, target, **kwargs):  # noqa: ANN001, ANN003
            raise asyncio.CancelledError

    monkeypatch.setattr(cli_main, "_default_engine", lambda: FakeEngine())
    monkeypatch.setattr(cli_main, "_default_history_store", lambda: FakeRecorder())
    monkeypatch.setattr(cli_main, "ScanTaskRunner", CancellingRunner)
    out, err = io.StringIO(), io.StringIO()
    code = run(["scan", str(target)], out=out, err=err)
    assert code == 5
    assert "cancelled" in err.getvalue()


def test_interrupted_scan_maps_to_exit_5_and_json(tmp_path, monkeypatch):
    """Simulate Ctrl+C: asyncio.run raises KeyboardInterrupt, exit code is 5."""
    target = tmp_path / "f"
    target.write_text("x")

    class NeverEndingEngine(BaseAVEngine):
        name = "slow"

        async def scan(self, target, *, recursive=True, profile=None):  # noqa: ANN001, ANN003
            await asyncio.sleep(60)

        async def update_signatures(self) -> str:  # pragma: no cover
            raise EngineError("unused")

    monkeypatch.setattr(cli_main, "_default_engine", lambda: NeverEndingEngine())
    monkeypatch.setattr(cli_main, "_default_history_store", lambda: FakeRecorder())

    def fake_run(coro):  # noqa: ANN001, ANN202
        coro.close()  # avoid "coroutine never awaited"
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_main.asyncio, "run", fake_run)
    out, err = io.StringIO(), io.StringIO()
    code = run(["scan", str(target), "--json"], out=out, err=err)
    assert code == 5
    payload = json.loads(out.getvalue())
    assert payload["status"] == "cancelled"
    assert payload["profile"] == "default"
    assert payload["target"] == str(target)
    assert "cancelled" in err.getvalue()


def test_engine_cancellation_reaps_before_cli_exits():
    """Core chain: runner → engine raises CancelledError after cleanup."""
    cleaned = {"done": False}

    class CancellingEngine(BaseAVEngine):
        name = "cancelling"

        async def scan(self, target, *, recursive=True, profile=None):  # noqa: ANN001, ANN003
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                cleaned["done"] = True  # subprocess reap would happen here
                raise
            raise AssertionError  # pragma: no cover

        async def update_signatures(self) -> str:  # pragma: no cover
            raise EngineError("unused")

    async def scenario():
        runner = ScanTaskRunner(CancellingEngine())
        task = runner.create_task(Path("/tmp/whatever"))
        await asyncio.sleep(0.01)
        await runner.cancel_all()
        return task.result() if not task.cancelled() else ScanResult.cancelled("/tmp/whatever")

    result = asyncio.run(asyncio.wait_for(scenario(), timeout=5))
    assert result.status is ScanStatus.CANCELLED
    assert cleaned["done"] is True


# ---------------------------------------------------------------------------
# M4-B5: Recorder / Controller wiring
# ---------------------------------------------------------------------------


def test_successful_scan_records_result(tmp_path, cli):
    """A clean scan is recorded once with the exact ScanResult produced."""
    target = tmp_path / "f"
    target.write_text("x")
    result = make_result(ScanStatus.CLEAN, target=str(target), files_scanned=2, engine="fake")
    recorder = FakeRecorder()
    harness = cli(FakeEngine(result), recorder=recorder)
    assert harness("scan", str(target)) == 0
    assert recorder.records == [result]


def test_detection_result_records_threats(tmp_path, cli):
    """An infected result is recorded and still maps to exit code 1."""
    target = tmp_path / "f"
    target.write_text("x")
    result = make_result(ScanStatus.INFECTED, target=str(target), threats=("Eicar-Test-Signature",))
    recorder = FakeRecorder()
    harness = cli(FakeEngine(result), recorder=recorder)
    assert harness("scan", str(target), "--json") == 1
    assert recorder.records == [result]
    assert recorder.records[0].threats == ("Eicar-Test-Signature",)
    assert json.loads(harness.out.getvalue())["status"] == "infected"


def test_scan_result_recorded_exactly_once(tmp_path, cli):
    """A single scan triggers exactly one record operation (no duplicate)."""
    target = tmp_path / "f"
    target.write_text("x")
    result = make_result(ScanStatus.CLEAN, target=str(target))
    recorder = FakeRecorder()
    harness = cli(FakeEngine(result), recorder=recorder)
    assert harness("scan", str(target)) == 0
    assert len(recorder.records) == 1


def test_scan_error_not_recorded(tmp_path, cli):
    """An engine error that never yields a ScanResult is not recorded."""
    target = tmp_path / "f"
    target.write_text("x")
    harness = cli(FakeEngine(exc=EngineError("clamscan not found")))
    assert harness("scan", str(target)) == 3
    assert harness.recorder.records == []


def test_recorder_failure_preserves_scan_result(tmp_path, cli):
    """A recording failure is logged but never alters the scan outcome."""
    target = tmp_path / "f"
    target.write_text("x")
    result = make_result(ScanStatus.INFECTED, target=str(target), threats=("Eicar",))
    recorder = FakeRecorder(exc=HistoryError("disk full"))
    harness = cli(FakeEngine(result), recorder=recorder)
    assert harness("scan", str(target), "--json") == 1
    assert "could not record scan history" in harness.err.getvalue()
    payload = json.loads(harness.out.getvalue())
    assert payload["status"] == "infected"
    assert payload["threats"] == ["Eicar"]


def test_history_store_open_failure_disables_recording(tmp_path, cli, monkeypatch):
    """An unavailable history layer disables recording without blocking the scan."""
    target = tmp_path / "f"
    target.write_text("x")
    harness = cli(FakeEngine(make_result(ScanStatus.CLEAN, target=str(target))))

    def broken_store() -> None:
        raise HistoryError("cannot open history database: permission denied")

    monkeypatch.setattr(cli_main, "_default_history_store", broken_store)
    assert harness("scan", str(target)) == 0
    assert "history recording disabled" in harness.err.getvalue()
    assert harness.recorder.records == []


def test_cancelled_scan_not_recorded(tmp_path, monkeypatch):
    """Cancellation yields no ScanResult at the boundary, so nothing is recorded."""
    target = tmp_path / "f"
    target.write_text("x")
    recorder = FakeRecorder()
    monkeypatch.setattr(cli_main, "_default_engine", lambda: FakeEngine())
    monkeypatch.setattr(cli_main, "_default_history_store", lambda: recorder)

    class CancellingRunner(ScanTaskRunner):
        async def submit(self, target, **kwargs):  # noqa: ANN001, ANN003
            raise asyncio.CancelledError

    monkeypatch.setattr(cli_main, "ScanTaskRunner", CancellingRunner)
    out, err = io.StringIO(), io.StringIO()
    code = run(["scan", str(target)], out=out, err=err)
    assert code == 5
    assert recorder.closed is True  # recorder released even on cancellation


# ---------------------------------------------------------------------------
# M4-B6: History reporting / query integration
# ---------------------------------------------------------------------------


def test_top_level_help_includes_history():
    """The ``history`` command is advertised in the top-level help."""
    out, err = io.StringIO(), io.StringIO()
    with pytest.raises(SystemExit) as excinfo:
        run(["--help"], out=out, err=err)
    assert excinfo.value.code == 0
    assert "history" in out.getvalue()


def test_history_list_empty(cli):
    """An empty history renders a clear, non-blank message."""
    harness = cli(FakeEngine(make_result(ScanStatus.CLEAN, target="/tmp/x")))
    assert harness("history", "list") == 0
    assert harness.out.getvalue().strip() == "No scan history found."


def test_history_list_empty_json(cli):
    """An empty history renders a JSON payload with a zero count."""
    harness = cli(FakeEngine(make_result(ScanStatus.CLEAN, target="/tmp/x")))
    assert harness("history", "list", "--json") == 0
    payload = json.loads(harness.out.getvalue())
    assert payload == {"count": 0, "records": []}


def test_history_list_shows_records(cli):
    """Recorded scans show up in the history list (newest first)."""
    recorder = FakeRecorder()
    asyncio.run(recorder.record_scan(make_result(ScanStatus.CLEAN, target="/tmp/first")))
    asyncio.run(recorder.record_scan(make_result(ScanStatus.INFECTED, target="/tmp/second")))
    harness = cli(FakeEngine(make_result(ScanStatus.CLEAN, target="/tmp/x")), recorder=recorder)
    assert harness("history", "list") == 0
    text = harness.out.getvalue()
    assert "Scan history:" in text
    assert "/tmp/second" in text
    assert "/tmp/first" in text
    # Newest first: "/tmp/second" appears before "/tmp/first".
    assert text.index("/tmp/second") < text.index("/tmp/first")


def test_history_list_json_contract(cli):
    """The JSON list payload exposes the deterministic record contract."""
    recorder = FakeRecorder()
    asyncio.run(recorder.record_scan(make_result(ScanStatus.CLEAN, target="/tmp/only")))
    harness = cli(FakeEngine(make_result(ScanStatus.CLEAN, target="/tmp/x")), recorder=recorder)
    assert harness("history", "list", "--json") == 0
    payload = json.loads(harness.out.getvalue())
    assert payload["count"] == 1
    (record,) = payload["records"]
    assert record["target"] == "/tmp/only"
    assert record["status"] == "clean"
    # Guaranteed key set, in contract order.
    assert list(record) == [
        "id",
        "status",
        "target",
        "engine",
        "profile",
        "threats",
        "files_scanned",
        "started_at",
        "finished_at",
        "duration_seconds",
        "error",
        "metadata",
    ]


def test_history_list_status_filter(cli):
    """The ``--status`` filter restricts the page to matching records."""
    recorder = FakeRecorder()
    asyncio.run(recorder.record_scan(make_result(ScanStatus.CLEAN, target="/tmp/clean")))
    asyncio.run(recorder.record_scan(make_result(ScanStatus.INFECTED, target="/tmp/infected")))
    harness = cli(FakeEngine(make_result(ScanStatus.CLEAN, target="/tmp/x")), recorder=recorder)
    assert harness("history", "list", "--status", "infected") == 0
    text = harness.out.getvalue()
    assert "/tmp/infected" in text
    assert "/tmp/clean" not in text


def test_history_list_limit(cli):
    """The ``--limit`` option caps the number of rows returned."""
    recorder = FakeRecorder()
    for index in range(5):
        asyncio.run(recorder.record_scan(make_result(ScanStatus.CLEAN, target=f"/tmp/{index}")))
    harness = cli(FakeEngine(make_result(ScanStatus.CLEAN, target="/tmp/x")), recorder=recorder)
    assert harness("history", "list", "--limit", "2", "--json") == 0
    payload = json.loads(harness.out.getvalue())
    assert payload["count"] == 2


def test_history_show_found(cli):
    """``history show`` renders a single record's full details."""
    recorder = FakeRecorder()
    asyncio.run(
        recorder.record_scan(
            make_result(ScanStatus.INFECTED, target="/tmp/bad", threats=("Eicar FOUND",))
        )
    )
    scan_id = list(recorder._stored)[0]
    harness = cli(FakeEngine(make_result(ScanStatus.CLEAN, target="/tmp/x")), recorder=recorder)
    assert harness("history", "show", scan_id) == 0
    text = harness.out.getvalue()
    assert scan_id in text
    assert "/tmp/bad" in text
    assert "INFECTED" in text
    assert "Eicar FOUND" in text


def test_history_show_json(cli):
    """``history show --json`` renders the deterministic record contract."""
    recorder = FakeRecorder()
    asyncio.run(recorder.record_scan(make_result(ScanStatus.CLEAN, target="/tmp/solo")))
    scan_id = list(recorder._stored)[0]
    harness = cli(FakeEngine(make_result(ScanStatus.CLEAN, target="/tmp/x")), recorder=recorder)
    assert harness("history", "show", scan_id, "--json") == 0
    record = json.loads(harness.out.getvalue())
    assert record["id"] == scan_id
    assert record["target"] == "/tmp/solo"
    assert record["status"] == "clean"


def test_history_show_not_found(cli):
    """An unknown id is reported as a usage error without crashing."""
    recorder = FakeRecorder()
    harness = cli(FakeEngine(make_result(ScanStatus.CLEAN, target="/tmp/x")), recorder=recorder)
    assert harness("history", "show", "does-not-exist") == 2
    assert "scan not found" in harness.err.getvalue()


def test_history_store_open_failure_reports_error(cli, monkeypatch):
    """A store that cannot be opened blocks the command with an error."""
    harness = cli(FakeEngine(make_result(ScanStatus.CLEAN, target="/tmp/x")))

    def broken_store() -> HistoryStore:
        raise HistoryError("cannot open history database: permission denied")

    monkeypatch.setattr(cli_main, "_default_history_store", broken_store)
    assert harness("history", "list") == 3
    assert "cannot open history store" in harness.err.getvalue()


def test_history_store_read_failure_reports_error(cli, monkeypatch):
    """A failure while querying surfaces as a runtime error, not a crash."""
    harness = cli(FakeEngine(make_result(ScanStatus.CLEAN, target="/tmp/x")))

    class FailingStore(FakeRecorder):
        async def list_scans(self, **kwargs: object) -> list[HistoryRecord]:  # noqa: ANN003
            raise HistoryError("disk read failure")

    monkeypatch.setattr(cli_main, "_default_history_store", FailingStore)
    assert harness("history", "list") == 3
    assert "cannot read history" in harness.err.getvalue()


def test_history_command_closes_store(cli):
    """The command releases the store connection before returning."""
    recorder = FakeRecorder()
    harness = cli(FakeEngine(make_result(ScanStatus.CLEAN, target="/tmp/x")), recorder=recorder)
    assert harness("history", "list") == 0
    assert recorder.closed is True


def test_history_listing_preserves_scan_result(cli):
    """Querying history never alters the stored scan outcomes."""
    recorder = FakeRecorder()
    asyncio.run(
        recorder.record_scan(
            make_result(ScanStatus.INFECTED, target="/tmp/bad", threats=("Eicar FOUND",))
        )
    )
    scan_id = list(recorder._stored)[0]
    harness = cli(FakeEngine(make_result(ScanStatus.CLEAN, target="/tmp/x")), recorder=recorder)
    assert harness("history", "list") == 0
    record = asyncio.run(recorder.get_scan(scan_id))
    assert record is not None
    assert record.status == "infected"
    assert record.threats == ("Eicar FOUND",)


# ---------------------------------------------------------------------------
# history purge
# ---------------------------------------------------------------------------


def test_history_purge_removes_all_with_future_before(cli) -> None:
    """``history purge --before <future>`` deletes every record."""
    recorder = FakeRecorder()
    asyncio.run(recorder.record_scan(make_result(ScanStatus.CLEAN, target="/tmp/old-1")))
    asyncio.run(recorder.record_scan(make_result(ScanStatus.INFECTED, target="/tmp/old-2")))
    harness = cli(FakeEngine(make_result(ScanStatus.CLEAN, target="/tmp/x")), recorder=recorder)
    assert harness("history", "purge", "--before", "9999-12-31T23:59:59+00:00") == 0
    text = harness.out.getvalue()
    assert "2 record" in text
    assert len(recorder._stored) == 0


def test_history_purge_no_match_with_past_before(cli) -> None:
    """``history purge --before <past>`` deletes nothing and reports zero."""
    recorder = FakeRecorder()
    asyncio.run(recorder.record_scan(make_result(ScanStatus.CLEAN, target="/tmp/recent")))
    harness = cli(FakeEngine(make_result(ScanStatus.CLEAN, target="/tmp/x")), recorder=recorder)
    assert harness("history", "purge", "--before", "2000-01-01T00:00:00+00:00") == 0
    text = harness.out.getvalue()
    assert "0 record" in text
    assert len(recorder._stored) == 1


def test_history_purge_status_filter(cli) -> None:
    """``--status`` restricts deletion to matching records only."""
    recorder = FakeRecorder()
    asyncio.run(recorder.record_scan(make_result(ScanStatus.CLEAN, target="/tmp/clean-1")))
    asyncio.run(recorder.record_scan(make_result(ScanStatus.INFECTED, target="/tmp/infected-1")))
    asyncio.run(recorder.record_scan(make_result(ScanStatus.CLEAN, target="/tmp/clean-2")))
    harness = cli(FakeEngine(make_result(ScanStatus.CLEAN, target="/tmp/x")), recorder=recorder)
    assert harness(
        "history", "purge", "--before", "9999-12-31T23:59:59+00:00", "--status", "clean"
    ) == 0
    text = harness.out.getvalue()
    assert "2 record" in text
    targets = sorted(r.target for r in recorder._stored.values())
    assert targets == ["/tmp/infected-1"]


def test_history_purge_requires_criteria(cli) -> None:
    """Without --before or --status the command refuses with a usage error."""
    recorder = FakeRecorder()
    asyncio.run(recorder.record_scan(make_result(ScanStatus.CLEAN, target="/tmp/x")))
    harness = cli(FakeEngine(make_result(ScanStatus.CLEAN, target="/tmp/x")), recorder=recorder)
    assert harness("history", "purge") == 2
    assert "at least one of --before / --status" in harness.err.getvalue()
    assert len(recorder._stored) == 1  # nothing deleted


def test_history_purge_invalid_timestamp(cli) -> None:
    """An unparseable timestamp is a usage error, exit code 2."""
    recorder = FakeRecorder()
    harness = cli(FakeEngine(make_result(ScanStatus.CLEAN, target="/tmp/x")), recorder=recorder)
    assert harness("history", "purge", "--before", "not-a-date") == 2
    assert "invalid timestamp" in harness.err.getvalue()


def test_history_purge_json_output(cli) -> None:
    """``--json`` emits a deterministic ``{"deleted": N}`` payload."""
    recorder = FakeRecorder()
    asyncio.run(recorder.record_scan(make_result(ScanStatus.CLEAN, target="/tmp/old")))
    harness = cli(FakeEngine(make_result(ScanStatus.CLEAN, target="/tmp/x")), recorder=recorder)
    assert harness(
        "history", "purge", "--before", "9999-12-31T23:59:59+00:00", "--json"
    ) == 0
    payload = json.loads(harness.out.getvalue())
    assert payload == {"deleted": 1}


def test_history_purge_store_open_failure(cli, monkeypatch) -> None:
    """A store that cannot be opened surfaces as a runtime error, exit 3."""
    harness = cli(FakeEngine(make_result(ScanStatus.CLEAN, target="/tmp/x")))

    def broken_store() -> HistoryStore:
        raise HistoryError("cannot open history database")

    monkeypatch.setattr(cli_main, "_default_history_store", broken_store)
    assert harness("history", "purge", "--before", "9999-12-31T23:59:59+00:00") == 3
    assert "cannot open history store" in harness.err.getvalue()


def test_history_purge_store_read_failure(cli, monkeypatch) -> None:
    """A failure while purging surfaces as a runtime error, exit 3."""
    harness = cli(FakeEngine(make_result(ScanStatus.CLEAN, target="/tmp/x")))

    class FailingStore(FakeRecorder):
        async def purge(
            self,
            *,
            before: datetime | None = None,
            status: str | None = None,
        ) -> int:
            raise HistoryError("disk write failure")

    monkeypatch.setattr(cli_main, "_default_history_store", FailingStore)
    assert harness("history", "purge", "--before", "9999-12-31T23:59:59+00:00") == 3
    assert "cannot purge history" in harness.err.getvalue()


def test_history_purge_closes_store(cli) -> None:
    """The command releases the store connection before returning."""
    recorder = FakeRecorder()
    asyncio.run(recorder.record_scan(make_result(ScanStatus.CLEAN, target="/tmp/x")))
    harness = cli(FakeEngine(make_result(ScanStatus.CLEAN, target="/tmp/x")), recorder=recorder)
    assert harness("history", "purge", "--before", "9999-12-31T23:59:59+00:00") == 0
    assert recorder.closed is True


def test_history_purge_does_not_affect_list_show(cli) -> None:
    """``history list`` and ``history show`` remain read-only after purge."""
    recorder = FakeRecorder()
    asyncio.run(recorder.record_scan(make_result(ScanStatus.CLEAN, target="/tmp/keep")))
    asyncio.run(recorder.record_scan(make_result(ScanStatus.INFECTED, target="/tmp/drop")))
    harness = cli(FakeEngine(make_result(ScanStatus.CLEAN, target="/tmp/x")), recorder=recorder)
    # Purge only infected records older than the future cutoff.
    assert harness(
        "history", "purge", "--before", "9999-12-31T23:59:59+00:00", "--status", "infected"
    ) == 0
    # history list shows only the preserved clean record.
    assert harness("history", "list") == 0
    assert "/tmp/keep" in harness.out.getvalue()
    assert "/tmp/drop" not in harness.out.getvalue()
