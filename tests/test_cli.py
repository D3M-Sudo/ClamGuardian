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


class CLI:
    """Small harness capturing run() output and injecting a fake engine."""

    def __init__(self, engine: BaseAVEngine, monkeypatch: pytest.MonkeyPatch):
        self.out = io.StringIO()
        self.err = io.StringIO()
        monkeypatch.setattr(cli_main, "_default_engine", lambda: engine)

    def __call__(self, *argv: str) -> int:
        self.out.seek(0)
        self.out.truncate()
        self.err.seek(0)
        self.err.truncate()
        return run(list(argv), out=self.out, err=self.err)


@pytest.fixture
def cli(monkeypatch: pytest.MonkeyPatch):
    def factory(engine: BaseAVEngine) -> CLI:
        return CLI(engine, monkeypatch)

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
