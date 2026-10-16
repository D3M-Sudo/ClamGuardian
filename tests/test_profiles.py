"""Tests for ScanProfile model, registry, and profile → engine translation."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from clamguardian.core.base import ScanResult
from clamguardian.core.errors import ProfileError
from clamguardian.core.profiles import (
    DEFAULT_PROFILE,
    DEFAULT_REGISTRY,
    ScanProfile,
    ScanProfileRegistry,
)
from clamguardian.core.runner import ScanTaskRunner
from clamguardian.engines.clamav import ClamAVEngine

# ---------------------------------------------------------------------------
# ScanProfile model
# ---------------------------------------------------------------------------


def test_profile_is_immutable() -> None:
    profile = ScanProfile.quick()
    with pytest.raises(AttributeError):
        profile.name = "hacked"  # type: ignore[misc]


def test_profile_valid_values_and_presets() -> None:
    for profile in DEFAULT_REGISTRY.list():
        assert profile.id and profile.name
        profile.validate()  # no raise
    assert DEFAULT_PROFILE.id == "default"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"id": "", "name": "x"},
        {"id": "x", "name": ""},
        {"id": "x", "name": "x", "max_filesize_mib": -5},
        {"id": "x", "name": "x", "max_filesize_mib": 0},
        {"id": "x", "name": "x", "max_scansize_mib": -1},
        {"id": "x", "name": "x", "max_recursion": 0},
        {"id": "x", "name": "x", "max_files": -3},
        # incompatible combination: scansize smaller than filesize
        {"id": "x", "name": "x", "max_filesize_mib": 100, "max_scansize_mib": 50},
    ],
)
def test_profile_invalid_values_raise(kwargs: dict) -> None:
    with pytest.raises(ProfileError):
        ScanProfile(**kwargs)


def test_with_overrides_returns_new_instance() -> None:
    custom = ScanProfile.custom().with_overrides(detect_pua=True, max_filesize_mib=10)
    assert custom.detect_pua is True
    assert custom.max_filesize_mib == 10
    assert custom.id == "custom"
    assert ScanProfile.custom().detect_pua is False  # original untouched


def test_quick_preset_semantics() -> None:
    quick = ScanProfile.quick()
    assert quick.recursive and quick.scan_archives
    assert not quick.scan_mail and not quick.detect_pua
    assert quick.max_filesize_mib == 25 and quick.max_scansize_mib == 100
    assert quick.max_recursion == 8


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_registry_get_and_list() -> None:
    ids = {p.id for p in DEFAULT_REGISTRY.list()}
    assert ids == {"quick", "home", "full", "custom"}
    assert DEFAULT_REGISTRY.get("quick") is not None
    assert "quick" in DEFAULT_REGISTRY and "nope" not in DEFAULT_REGISTRY


def test_registry_unknown_profile_raises() -> None:
    with pytest.raises(ProfileError, match="unknown scan profile"):
        DEFAULT_REGISTRY.get("nope")


def test_registry_validates_on_register() -> None:
    registry = ScanProfileRegistry()
    with pytest.raises(ProfileError):
        registry.register(ScanProfile(id="bad", name="bad", max_filesize_mib=-1))
    custom = ScanProfile.custom().with_overrides(max_filesize_mib=5)
    registry.register(custom)
    assert registry.get("custom") is custom


def test_registry_custom_registry_is_isolated() -> None:
    registry = ScanProfileRegistry([ScanProfile.home()])
    assert [p.id for p in registry.list()] == ["home"]


# ---------------------------------------------------------------------------
# Profile → engine translation (engine layer only)
# ---------------------------------------------------------------------------


def test_clamscan_args_default_profile() -> None:
    args = ClamAVEngine._clamscan_args(DEFAULT_PROFILE)
    assert args == ["--recursive", "--scan-archive=yes", "--scan-mail=yes"]


def test_clamscan_args_quick_preset() -> None:
    args = ClamAVEngine._clamscan_args(ScanProfile.quick())
    assert args == [
        "--recursive",
        "--scan-archive=yes",
        "--scan-mail=no",
        "--max-filesize=25M",
        "--max-scansize=100M",
        "--max-recursion=8",
    ]


def test_clamscan_args_full_preset() -> None:
    args = ClamAVEngine._clamscan_args(ScanProfile.full())
    assert "--pua" in args
    assert not any(a.startswith("--max-") for a in args)  # no limits


def test_clamscan_args_symlink_policy() -> None:
    follow = ClamAVEngine._clamscan_args(ScanProfile.custom().with_overrides(follow_symlinks=True))
    nofollow = ClamAVEngine._clamscan_args(
        ScanProfile.custom().with_overrides(follow_symlinks=False)
    )
    assert "--follow-symlinks" in follow and "--nofollow-symlinks" in nofollow


@pytest.mark.asyncio
async def test_engine_scan_applies_profile_to_cli(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "d"
    target.mkdir()
    engine = ClamAVEngine(socket_path=tmp_path / "missing.sock")
    captured: list[list[str]] = []

    async def fake_command(args):
        captured.append(list(args))
        return f"{target}: OK\n", 0

    monkeypatch.setattr(engine, "_run_command", fake_command)
    await engine.scan(target, profile=ScanProfile.quick())
    assert captured[0][:2] == ["clamscan", "--no-summary"]
    assert "--max-filesize=25M" in captured[0]
    assert captured[0][-1] == str(target)


@pytest.mark.asyncio
async def test_engine_rejects_invalid_profile(tmp_path: Path) -> None:
    engine = ClamAVEngine(socket_path=tmp_path / "missing.sock")
    bad = ScanProfile.custom().with_overrides(max_scansize_mib=1)
    object.__setattr__(bad, "max_filesize_mib", 10)  # simulate post-construction corruption
    with pytest.raises(ProfileError):
        await engine.scan(tmp_path, profile=bad)


@pytest.mark.asyncio
async def test_engine_backward_compatible_scan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Old ``scan(target, recursive=...)`` calls keep working."""
    target = tmp_path / "f.txt"
    target.write_text("x")
    engine = ClamAVEngine(socket_path=tmp_path / "missing.sock")

    async def fake_command(args):
        return f"{target}: OK\n", 0

    monkeypatch.setattr(engine, "_run_command", fake_command)
    result = await engine.scan(target, recursive=False)
    assert result.metadata["profile_id"] == "default"
    assert result.clean is True
    non_recursive_args = engine._clamscan_args(DEFAULT_PROFILE.with_overrides(recursive=False))
    assert "--recursive" not in non_recursive_args


# ---------------------------------------------------------------------------
# clamd-specific behaviour
# ---------------------------------------------------------------------------


def test_clamd_unsupported_set_matches_profile() -> None:
    quiet = ScanProfile.custom().with_overrides(scan_mail=False, detect_pua=True)
    unsupported = ClamAVEngine._clamd_unsupported_options(quiet)
    assert set(unsupported) == {"scan_mail", "detect_pua"}
    assert ClamAVEngine._clamd_unsupported_options(ScanProfile.custom()) == ()
    assert "max_filesize_mib" in ClamAVEngine._clamd_unsupported_options(ScanProfile.quick())


@pytest.mark.asyncio
async def test_clamd_reports_unsupported_options(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Options clamd cannot honour per-connection are reported, not dropped."""
    import clamguardian.engines.clamav as clamav_mod

    sock = tmp_path / "clamd.ctl"
    sock.write_text("")  # make socket_path.exists() true

    class FakeWriter:
        def write(self, data: bytes) -> None:
            FakeWriter.sent = data

        async def drain(self) -> None:
            return None

        def close(self) -> None:
            return None

        async def wait_closed(self) -> None:
            return None

    class FakeReader:
        async def read(self, n: int) -> bytes:
            if not getattr(FakeReader, "read_once", False):
                FakeReader.read_once = True
                return b"/tmp/x: OK\n"
            return b""

    async def fake_connection(path):
        return FakeReader(), FakeWriter()

    monkeypatch.setattr(clamav_mod.asyncio, "open_unix_connection", fake_connection)
    engine = ClamAVEngine(socket_path=sock)
    result = await engine.scan(tmp_path, profile=ScanProfile.quick())
    assert result.engine == "clamd"
    unsupported = result.metadata["profile_unsupported_clamd"].split(",")
    assert "max_filesize_mib" in unsupported
    assert "scan_mail" in unsupported
    assert result.metadata["profile_id"] == "quick"
    assert FakeWriter.sent.startswith(b"CONTSCAN ")  # recursive dir → CONTSCAN


# ---------------------------------------------------------------------------
# Profile passthrough: Runner → Engine, Controller → Runner
# ---------------------------------------------------------------------------


class RecordingEngine:
    """Duck-typed engine recording the profile it received."""

    name = "recording"

    def __init__(self) -> None:
        self.profiles: list[object] = []

    async def scan(self, target: Path, *, recursive: bool = True, profile=None) -> ScanResult:
        self.profiles.append(profile)
        return ScanResult(target=str(target), clean=True)

    async def update_signatures(self) -> str:
        return ""


@pytest.mark.asyncio
async def test_runner_forwards_profile_untouched() -> None:
    engine = RecordingEngine()
    runner = ScanTaskRunner(engine)  # type: ignore[arg-type]
    profile = ScanProfile.quick()
    await runner.submit(Path("/tmp/x"), profile=profile)
    assert engine.profiles == [profile]

    engine2 = RecordingEngine()
    runner2 = ScanTaskRunner(engine2)  # type: ignore[arg-type]
    runner2.create_task(Path("/tmp/y"), profile=profile)
    await asyncio.sleep(0.01)
    assert engine2.profiles == [profile]


@pytest.mark.asyncio
async def test_runner_default_profile_is_none() -> None:
    engine = RecordingEngine()
    runner = ScanTaskRunner(engine)  # type: ignore[arg-type]
    await runner.submit(Path("/tmp/x"))
    assert engine.profiles == [None]


@pytest.mark.asyncio
async def test_controller_forwards_profile_untouched() -> None:
    """GTK layer passes ScanProfile objects, never CLI strings."""
    from clamguardian.ui.controller import ShieldTaskController

    engine = RecordingEngine()
    controller = ShieldTaskController(engine)  # type: ignore[arg-type]
    profile = ScanProfile.full()
    await controller.scan(Path("/tmp/z"), profile=profile)
    assert engine.profiles == [profile]

