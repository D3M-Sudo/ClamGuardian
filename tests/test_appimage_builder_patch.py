"""Regression tests for the guarded appimage-builder compatibility patch."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATCHER = ROOT / "packaging" / "appimage" / "patch-appimage-builder.py"
CI = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE = ROOT / ".github" / "workflows" / "release.yml"

ORIGINAL = """from packaging import version


class Package:
    def __gt__(self, other):
        if isinstance(other, Package):
            return version.parse(self.version) > version.parse(other.version)
"""
APPRUN2_ORIGINAL = """import string


class AppRunV2Setup:
    def setup(self):
        self.move_glibc_to_compat_runtime()
        runtime_env = self._configure_runtime_environment()
"""


def test_appimage_builder_patch_uses_native_debian_version_ordering(tmp_path: Path) -> None:
    site_packages = tmp_path / "lib/python3.12/site-packages"
    package_module = site_packages / "appimagebuilder/modules/deploy/apt/package.py"
    apprun_module = site_packages / "appimagebuilder/modules/setup/apprun_2/apprun2.py"
    package_module.parent.mkdir(parents=True)
    apprun_module.parent.mkdir(parents=True)
    package_module.write_text(ORIGINAL, encoding="utf-8")
    apprun_module.write_text(APPRUN2_ORIGINAL, encoding="utf-8")

    subprocess.run([sys.executable, str(PATCHER), str(tmp_path)], check=True)
    patched = package_module.read_text(encoding="utf-8")
    assert "import subprocess" in patched
    assert '["dpkg", "--compare-versions", self.version, "gt", other.version]' in patched
    assert "version.parse(" not in patched
    assert "result.returncode not in (0, 1)" in patched

    apprun_patched = apprun_module.read_text(encoding="utf-8")
    assert "import shutil\n" in apprun_patched
    assert 'compat_linker_folder = self.compat_runtime_path / "lib64"' in apprun_patched
    assert '"*/*-linux-gnu*/ld-linux*.so*"' in apprun_patched
    assert "compat_linker_folder.symlink_to(symlink_target)" in apprun_patched
    assert "x86_64-linux-gnu" not in apprun_patched

    subprocess.run([sys.executable, str(PATCHER), str(tmp_path)], check=True)
    assert package_module.read_text(encoding="utf-8") == patched
    assert apprun_module.read_text(encoding="utf-8") == apprun_patched


def test_appimage_builder_patch_fails_closed_on_unknown_upstream_source(tmp_path: Path) -> None:
    package_module = (
        tmp_path
        / "lib/python3.12/site-packages/appimagebuilder/modules/deploy/apt/package.py"
    )
    package_module.parent.mkdir(parents=True)
    package_module.write_text("class Package: pass\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(PATCHER), str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "Unexpected appimage-builder" in result.stderr


def test_flatpak_ci_and_release_verify_the_installed_ref_architecture() -> None:
    for workflow in (CI, RELEASE):
        text = workflow.read_text(encoding="utf-8")
        assert "--show-ref" in text
        assert "--show-arch" not in text
        expected_ref = "app/io.github.clamguardian.ClamGuardian/" + "${{ matrix.arch }}" + "/master"
        assert expected_ref in text
