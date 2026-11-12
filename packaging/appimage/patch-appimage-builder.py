#!/usr/bin/env python3
"""Patch appimage-builder 1.1.0 for Debian versions and Ubuntu AppRun layout."""
from __future__ import annotations

import sys
from pathlib import Path

ORIGINAL_IMPORT = "from packaging import version"
ORIGINAL_COMPARISON = "return version.parse(self.version) > version.parse(other.version)"
PATCH_MARKER = '["dpkg", "--compare-versions", self.version, "gt", other.version]'
REPLACEMENT = '''result = subprocess.run(
                ["dpkg", "--compare-versions", self.version, "gt", other.version],
                check=False,
            )
            if result.returncode not in (0, 1):
                raise RuntimeError(
                    f"dpkg could not compare package versions {self.version!r} "
                    f"and {other.version!r} (exit {result.returncode})"
                )
            return result.returncode == 0'''


def patch_package_module(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    if PATCH_MARKER in source:
        return
    if ORIGINAL_IMPORT not in source or ORIGINAL_COMPARISON not in source:
        raise RuntimeError(
            "Unexpected appimage-builder apt/package.py source; "
            "refusing an unreviewed patch."
        )
    source = source.replace(ORIGINAL_IMPORT, "import subprocess", 1)
    source = source.replace(ORIGINAL_COMPARISON, REPLACEMENT, 1)
    path.write_text(source, encoding="utf-8")


APPRUN2_SETUP_MARKER = 'compat_linker_folder = self.compat_runtime_path / "lib64"'
APPRUN2_SETUP_ORIGINAL = """    def setup(self):
        self.move_glibc_to_compat_runtime()
        runtime_env = self._configure_runtime_environment()
"""
APPRUN2_SETUP_REPLACEMENT = """    def setup(self):
        self.move_glibc_to_compat_runtime()
        compat_linker_folder = self.compat_runtime_path / "lib64"
        if compat_linker_folder.is_symlink() or compat_linker_folder.is_file():
            compat_linker_folder.unlink()
        elif compat_linker_folder.is_dir():
            shutil.rmtree(compat_linker_folder)
        linker = self.finder.find_one(
            "*/*-linux-gnu*/ld-linux*.so*",
            [Finder.is_file, Finder.is_elf_shared_lib],
        )
        if linker is None:
            raise RuntimeError(
                "Unable to find the dynamic linker under a *-linux-gnu* "
                f"directory in {self.appdir_path}"
            )
        linker_folder = linker.parent
        symlink_target = linker_folder.relative_to(compat_linker_folder.parent)
        compat_linker_folder.symlink_to(symlink_target)
        runtime_env = self._configure_runtime_environment()
"""


def patch_apprun2_module(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    if APPRUN2_SETUP_MARKER in source:
        return
    if APPRUN2_SETUP_ORIGINAL not in source:
        raise RuntimeError(
            "Unexpected appimage-builder AppRun v2 setup source; "
            "refusing an unreviewed patch."
        )
    source = source.replace(APPRUN2_SETUP_ORIGINAL, APPRUN2_SETUP_REPLACEMENT, 1)
    if "import shutil\n" not in source:
        source = source.replace("import string\n", "import string\nimport shutil\n", 1)
    path.write_text(source, encoding="utf-8")


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: patch-appimage-builder.py BUILDER_VENV")
    root = Path(sys.argv[1])
    package_modules = list(
        root.glob("lib/python*/site-packages/appimagebuilder/modules/deploy/apt/package.py")
    )
    if len(package_modules) != 1:
        raise SystemExit(
            "expected exactly one appimage-builder apt/package.py under "
            f"{root}, found {len(package_modules)}"
        )
    patch_package_module(package_modules[0])
    print(f"Patched Debian version comparison in {package_modules[0]}")

    apprun2_modules = list(
        root.glob("lib/python*/site-packages/appimagebuilder/modules/setup/apprun_2/apprun2.py")
    )
    if len(apprun2_modules) != 1:
        raise SystemExit(
            f"expected exactly one AppRun v2 module under {root}, "
            f"found {len(apprun2_modules)}"
        )
    patch_apprun2_module(apprun2_modules[0])
    print(f"Patched Ubuntu compatibility linker path in {apprun2_modules[0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
