#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
: "${APP_VERSION:?APP_VERSION must be set}"
: "${APT_ARCH:?APT_ARCH must be amd64 or arm64}"
: "${APPIMAGE_ARCH:?APPIMAGE_ARCH must be x86_64 or aarch64}"
WHEELHOUSE="$ROOT/packaging/appimage/wheelhouse"
find "$WHEELHOUSE" -maxdepth 1 -type f -name '*.whl' -print -quit | grep -q . || { echo "Empty AppImage wheelhouse" >&2; exit 1; }
sudo apt-get update
sudo apt-get install -y librsvg2-bin squashfs-tools
BUILDER_ENV="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/appimage-builder-venv"
python3 -m venv "$BUILDER_ENV"
"$BUILDER_ENV/bin/python" -m pip install --disable-pip-version-check "appimage-builder==1.0.0"
export APP_VERSION APT_ARCH APPIMAGE_ARCH
cd "$ROOT"
"$BUILDER_ENV/bin/appimage-builder" --recipe packaging/appimage/AppImageBuilder.yml --skip-test
mkdir -p "$ROOT/dist"
find "$ROOT" -maxdepth 1 -type f -name "ClamGuardian-$APP_VERSION-$APPIMAGE_ARCH.AppImage" -exec mv {} "$ROOT/dist/" \;
test -x "$ROOT/dist/ClamGuardian-$APP_VERSION-$APPIMAGE_ARCH.AppImage"
