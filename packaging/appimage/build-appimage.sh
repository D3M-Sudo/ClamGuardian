#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
: "${APP_VERSION:?APP_VERSION must be set}"
: "${APPIMAGE_ARCH:?APPIMAGE_ARCH must be x86_64 or aarch64}"

case "$APPIMAGE_ARCH" in
    x86_64) expected_deb_arch="amd64" ;;
    aarch64) expected_deb_arch="arm64" ;;
    *) echo "Unsupported AppImage architecture: $APPIMAGE_ARCH" >&2; exit 1 ;;
esac

actual_arch="$(dpkg --print-architecture)"
test "$actual_arch" = "$expected_deb_arch" || {
    echo "Native build mismatch: expected $expected_deb_arch, got $actual_arch" >&2
    exit 1
}

WHEELHOUSE="$ROOT/packaging/appimage/wheelhouse"
find "$WHEELHOUSE" -maxdepth 1 -type f -name '*.whl' -print -quit | grep -q . || {
    echo "Empty AppImage wheelhouse" >&2
    exit 1
}

sudo apt-get update
sudo apt-get install -y \
    curl python3.12 python3.12-minimal libpython3.12-minimal libpython3.12-stdlib \
    python3-gi python3-cairo \
    gir1.2-gtk-4.0 gir1.2-adw-1 gir1.2-secret-1 \
    libgtk-4-1 libadwaita-1-0 libsecret-1-0 \
    libgdk-pixbuf-2.0-0 libgdk-pixbuf2.0-bin librsvg2-common \
    adwaita-icon-theme hicolor-icon-theme gsettings-desktop-schemas \
    libglib2.0-bin ca-certificates \
    xvfb xauth dbus-x11 file squashfs-tools

SYSTEM_PYTHON=/usr/bin/python3.12
test "$("$SYSTEM_PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')" = "3.12"
"$SYSTEM_PYTHON" -c 'import gi, cairo; from gi.repository import Gtk, Adw, Secret; print("System GTK/GI runtime OK")'
test -d /usr/lib/python3.12/encodings

APPDIR="$ROOT/build/appimage/AppDir"
rm -rf "$APPDIR"
mkdir -p \
    "$APPDIR/usr/bin" \
    "$APPDIR/usr/lib" \
    "$APPDIR/usr/lib/python3/dist-packages" \
    "$APPDIR/opt/python" \
    "$APPDIR/usr/share/clamguardian"

# Copy native Ubuntu 24.04 CPython 3.12. PYTHONHOME points to AppDir; the
# relative lib/python3.12 symlink maps the standard library into /usr/lib.
install -Dm755 /usr/bin/python3.12 "$APPDIR/usr/bin/python3.12"
ln -sfn python3.12 "$APPDIR/usr/bin/python3"
cp -a /usr/lib/python3.12 "$APPDIR/usr/lib/python3.12"
mkdir -p "$APPDIR/lib"
ln -sfn ../usr/lib/python3.12 "$APPDIR/lib/python3.12"

# Install only the hash-verified, native-architecture runtime wheels.
python -m pip install --no-index --no-deps --target "$APPDIR/opt/python" "$WHEELHOUSE"/*.whl
cp -a "$ROOT/clamguardian" "$APPDIR/opt/python/"

# The AppRun is a small, auditable shell entrypoint; no generated AppRun patch.
install -Dm755 "$ROOT/packaging/appimage/AppRun" "$APPDIR/AppRun"
install -Dm644 "$ROOT/data/io.github.clamguardian.ClamGuardian.desktop" \
    "$APPDIR/io.github.clamguardian.ClamGuardian.desktop"
sed -i 's/^Exec=.*/Exec=AppRun ui/' "$APPDIR/io.github.clamguardian.ClamGuardian.desktop"
install -Dm644 "$ROOT/data/icons/hicolor/scalable/apps/io.github.clamguardian.ClamGuardian.svg" \
    "$APPDIR/usr/share/icons/hicolor/scalable/apps/io.github.clamguardian.ClamGuardian.svg"
ln -sfn "usr/share/icons/hicolor/scalable/apps/io.github.clamguardian.ClamGuardian.svg" "$APPDIR/.DirIcon"
install -Dm755 "$ROOT/packaging/smoke/gtk-smoke.py" \
    "$APPDIR/usr/share/clamguardian/gtk-smoke.py"

export APPIMAGE_ARCH
"$ROOT/packaging/appimage/bundle-runtime.sh" "$APPDIR"

# Validate the AppDir before creating the single-file artifact.
"$APPDIR/AppRun" version
"$APPDIR/AppRun" profiles
GTK_A11Y=none xvfb-run -a dbus-run-session -- \
    "$APPDIR/AppRun" --python-interpreter "$APPDIR/usr/share/clamguardian/gtk-smoke.py"

. "$ROOT/packaging/appimage/install-appimagetool.sh"
mkdir -p "$ROOT/dist"
output="$ROOT/dist/ClamGuardian-$APP_VERSION-$APPIMAGE_ARCH.AppImage"
rm -f "$output"
appimagetool "$APPDIR" "$output"
chmod +x "$output"
test -s "$output"
echo "Built native AppImage: $output"
