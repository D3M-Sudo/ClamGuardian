"""Tests for the Core dependency diagnostics (desktop UI phase D1).

Every probe boundary (``which``, socket paths, ``/proc`` root, database
directories, environment) is injected, so the suite runs deterministically on
any machine — no ClamAV installation and no daemon required.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from clamguardian.core.diagnostics import (
    CheckStatus,
    critical_missing,
    detect_distro_family,
    run_dependency_checks,
    summarize,
)

NOW = datetime(2026, 10, 18, 12, 0, 0, tzinfo=UTC)


def _which(present: set[str]):
    """Build a fake ``shutil.which`` resolving exactly *present* names."""

    def lookup(name: str) -> str | None:
        return f"/usr/bin/{name}" if name in present else None

    return lookup


def _check_by_id(results, check_id):
    return next(result for result in results if result.id == check_id)


def test_all_present_and_healthy(tmp_path: Path) -> None:
    socket = tmp_path / "clamd.sock"
    socket.touch()
    proc_root = tmp_path / "proc"
    (proc_root / "1234").mkdir(parents=True)
    (proc_root / "1234" / "comm").write_text("clamd\n")
    db_dir = tmp_path / "clamav"
    db_dir.mkdir()
    (db_dir / "main.cvd").touch()

    results = run_dependency_checks(
        which=_which({"clamscan", "clamdscan", "freshclam"}),
        env={},
        socket_paths=[socket],
        database_dirs=[db_dir],
        proc_root=proc_root,
        now=NOW,
    )

    assert [result.id for result in results] == [
        "clamscan",
        "clamdscan",
        "freshclam",
        "clamd",
        "databases",
        "flatpak",
    ]
    assert all(result.status is CheckStatus.OK for result in results)
    assert critical_missing(results) == []
    assert summarize(results) == {"ok": 6, "warning": 0, "missing": 0}


def test_missing_clamscan_is_critical_and_carries_remedies(tmp_path: Path) -> None:
    results = run_dependency_checks(
        which=_which(set()),
        env={},
        socket_paths=[tmp_path / "missing.sock"],
        database_dirs=[tmp_path / "no-db"],
        proc_root=tmp_path / "empty-proc",
        now=NOW,
    )

    clamscan = _check_by_id(results, "clamscan")
    assert clamscan.status is CheckStatus.MISSING
    assert clamscan.critical is True
    assert set(clamscan.remedies) == {"debian", "fedora", "arch"}

    # clamdscan / freshclam missing are reported but not critical.
    assert _check_by_id(results, "clamdscan").critical is False
    assert _check_by_id(results, "freshclam").critical is False

    missing = critical_missing(results)
    assert [result.id for result in missing] == ["clamscan", "databases"]


def test_daemon_running_with_socket_is_ok(tmp_path: Path) -> None:
    socket = tmp_path / "clamd.sock"
    socket.touch()
    proc_root = tmp_path / "proc"
    (proc_root / "7").mkdir(parents=True)
    (proc_root / "7" / "comm").write_text("clamd\n")

    results = run_dependency_checks(
        which=_which({"clamscan", "clamdscan"}),
        env={},
        socket_paths=[socket],
        database_dirs=[tmp_path / "db"],
        proc_root=proc_root,
        now=NOW,
    )
    daemon = _check_by_id(results, "clamd")
    assert daemon.status is CheckStatus.OK
    assert daemon.remedies == {}


def test_daemon_socket_without_process_is_warning(tmp_path: Path) -> None:
    socket = tmp_path / "clamd.sock"
    socket.touch()
    results = run_dependency_checks(
        which=_which({"clamscan", "clamdscan"}),
        env={},
        socket_paths=[socket],
        database_dirs=[tmp_path / "db"],
        proc_root=tmp_path / "empty-proc",
        now=NOW,
    )
    daemon = _check_by_id(results, "clamd")
    assert daemon.status is CheckStatus.WARNING
    assert "no clamd process detected" in daemon.detail
    assert daemon.critical is False


def test_daemon_stopped_falls_back_to_clamscan(tmp_path: Path) -> None:
    results = run_dependency_checks(
        which=_which({"clamscan", "clamdscan"}),
        env={},
        socket_paths=[tmp_path / "missing.sock"],
        database_dirs=[tmp_path / "db"],
        proc_root=tmp_path / "empty-proc",
        now=NOW,
    )
    daemon = _check_by_id(results, "clamd")
    assert daemon.status is CheckStatus.WARNING
    assert "fall back to clamscan" in daemon.detail


def test_daemon_not_installed_is_missing_but_not_critical(tmp_path: Path) -> None:
    results = run_dependency_checks(
        which=_which({"clamscan", "freshclam"}),
        env={},
        socket_paths=[tmp_path / "missing.sock"],
        database_dirs=[tmp_path / "db"],
        proc_root=tmp_path / "empty-proc",
        now=NOW,
    )
    daemon = _check_by_id(results, "clamd")
    assert daemon.status is CheckStatus.MISSING
    assert daemon.critical is False
    assert critical_missing(results) == [
        result for result in results if result.id == "databases"
    ]


def test_no_signature_databases_is_critical_warning(tmp_path: Path) -> None:
    results = run_dependency_checks(
        which=_which({"clamscan"}),
        env={},
        socket_paths=[tmp_path / "missing.sock"],
        database_dirs=[tmp_path / "empty"],
        proc_root=tmp_path / "empty-proc",
        now=NOW,
    )
    databases = _check_by_id(results, "databases")
    assert databases.status is CheckStatus.WARNING
    assert databases.critical is True
    assert "freshclam" in databases.detail
    assert databases.remedies["debian"] == "sudo freshclam"


def test_stale_signature_databases_are_reported(tmp_path: Path) -> None:
    db_dir = tmp_path / "clamav"
    db_dir.mkdir()
    cvd = db_dir / "main.cvd"
    cvd.touch()
    stale = NOW - timedelta(days=20)
    import os

    os.utime(cvd, (stale.timestamp(), stale.timestamp()))

    results = run_dependency_checks(
        which=_which({"clamscan"}),
        env={},
        socket_paths=[tmp_path / "missing.sock"],
        database_dirs=[db_dir],
        proc_root=tmp_path / "empty-proc",
        now=NOW,
    )
    databases = _check_by_id(results, "databases")
    assert databases.status is CheckStatus.WARNING
    assert "20 days old" in databases.detail


def test_fresh_signature_databases_are_ok(tmp_path: Path) -> None:
    db_dir = tmp_path / "clamav"
    db_dir.mkdir()
    (db_dir / "main.cvd").touch()

    results = run_dependency_checks(
        which=_which({"clamscan"}),
        env={},
        socket_paths=[tmp_path / "missing.sock"],
        database_dirs=[db_dir],
        proc_root=tmp_path / "empty-proc",
        now=NOW,
    )
    databases = _check_by_id(results, "databases")
    assert databases.status is CheckStatus.OK
    assert databases.remedies == {}


def test_flatpak_sandbox_is_reported(tmp_path: Path) -> None:
    results = run_dependency_checks(
        which=_which({"clamscan"}),
        env={"FLATPAK_ID": "io.github.clamguardian.ClamGuardian"},
        socket_paths=[tmp_path / "missing.sock"],
        database_dirs=[tmp_path / "db"],
        proc_root=tmp_path / "empty-proc",
        now=NOW,
    )
    environment = _check_by_id(results, "flatpak")
    assert environment.status is CheckStatus.OK
    assert "flatpak-spawn --host" in environment.detail


def test_default_which_falls_back_to_host_inside_sandbox(
    tmp_path: Path, monkeypatch
) -> None:
    """Inside the sandbox an unfound binary is resolved on the host."""
    import clamguardian.core.diagnostics as diagnostics

    calls: list[str] = []

    def fake_host_which(name: str) -> str | None:
        calls.append(name)
        return f"/host/bin/{name}" if name == "clamscan" else None

    monkeypatch.setattr(diagnostics, "_host_which", fake_host_which)
    monkeypatch.setattr(diagnostics.shutil, "which", lambda name: None)

    results = diagnostics.run_dependency_checks(
        env={"FLATPAK_ID": "io.github.clamguardian.ClamGuardian"},
        socket_paths=[tmp_path / "missing.sock"],
        database_dirs=[tmp_path / "db"],
        proc_root=tmp_path / "empty-proc",
        now=NOW,
    )
    assert _check_by_id(results, "clamscan").detail == "/host/bin/clamscan"
    assert "clamscan" in calls


def test_default_which_does_not_call_host_outside_sandbox(monkeypatch) -> None:
    import clamguardian.core.diagnostics as diagnostics

    calls: list[str] = []
    monkeypatch.setattr(
        diagnostics, "_host_which", lambda name: calls.append(name) or None
    )
    monkeypatch.setattr(diagnostics.shutil, "which", lambda name: None)

    diagnostics.run_dependency_checks(
        env={},
        socket_paths=[Path("/nonexistent/clamd.sock")],
        database_dirs=[Path("/nonexistent/clamav")],
        proc_root=Path("/nonexistent/proc"),
        now=NOW,
    )
    assert calls == []


def test_detect_distro_family(tmp_path: Path) -> None:
    def write_os_release(content: str) -> Path:
        path = tmp_path / "os-release"
        path.write_text(content)
        return path

    assert detect_distro_family(write_os_release('ID=ubuntu\nID_LIKE="debian"\n')) == "debian"
    assert detect_distro_family(write_os_release("ID=linuxmint\nID_LIKE=ubuntu debian\n")) == (
        "debian"
    )
    assert detect_distro_family(write_os_release("ID=fedora\n")) == "fedora"
    assert detect_distro_family(write_os_release("ID=manjaro\nID_LIKE=arch\n")) == "arch"
    assert detect_distro_family(write_os_release("ID=someos\n")) == "unknown"
    assert detect_distro_family(tmp_path / "missing-file") == "unknown"