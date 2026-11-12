#!/usr/bin/env bash
set -euo pipefail

APPIMAGE="$(realpath "${1:?usage: test-appimage.sh /path/to/ClamGuardian.AppImage}")"
test -x "$APPIMAGE"
expected_arch="${APPIMAGE_ARCH:-$(uname -m)}"
actual_arch="$(uname -m)"
file_description="$(file "$APPIMAGE")"

case "$expected_arch" in
    x86_64) grep -Eq 'x86-64|x86_64' <<<"$file_description" ;;
    aarch64) grep -Eq 'ARM aarch64|AArch64' <<<"$file_description" ;;
    *) echo "Unsupported expected architecture: $expected_arch" >&2; exit 1 ;;
esac
test "$actual_arch" = "$expected_arch" || {
    echo "Native runner mismatch: expected $expected_arch, got $actual_arch" >&2
    exit 1
}

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
deployed="$tmpdir/ClamGuardian.AppImage"
install -m755 "$APPIMAGE" "$deployed"

extract_root="$tmpdir/extracted"
mkdir -p "$extract_root"
(cd "$extract_root" && "$deployed" --appimage-extract >/dev/null)
extracted_appdir="$extract_root/squashfs-root"

test -x "$extracted_appdir/AppRun"
test -f "$extracted_appdir/io.github.clamguardian.ClamGuardian.svg"
test -f "$extracted_appdir/usr/share/applications/io.github.clamguardian.ClamGuardian.desktop"
test -x "$extracted_appdir/usr/bin/python3"
test -x "$extracted_appdir/usr/bin/gdk-pixbuf-query-loaders"
test -f "$extracted_appdir/lib/python3.12/encodings/__init__.py"
test -d "$extracted_appdir/usr/lib/python3/dist-packages/gi"
test -d "$extracted_appdir/usr/lib/girepository-1.0"
test -f "$extracted_appdir/usr/share/clamguardian/gtk-smoke.py"
test -f "$extracted_appdir/usr/share/glib-2.0/schemas/gschemas.compiled"
test -f "$extracted_appdir/etc/ssl/certs/ca-certificates.crt"
test -f "$extracted_appdir/usr/lib/$(/usr/bin/python3.12 -c 'import sysconfig; print(sysconfig.get_config_var("MULTIARCH"))')/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-svg.so"

for pattern in \
    'libgtk-4.so.1*' \
    'libadwaita-1.so.0*' \
    'libsecret-1.so.0*' \
    'libgirepository-*.so.*'; do
    find "$extracted_appdir/usr/lib" -name "$pattern" -print -quit | grep -q . || {
        echo "AppImage is missing bundled runtime library: $pattern" >&2
        exit 1
    }
done

for typelib in Gtk-4.0.typelib Adw-1.typelib Secret-1.typelib; do
    find "$extracted_appdir/usr/lib" -path '*/girepository-1.0/*' -name "$typelib" -print -quit | grep -q . || {
        echo "AppImage is missing GI typelib: $typelib" >&2
        exit 1
    }
done

version_output="$(APPIMAGE_EXTRACT_AND_RUN=1 "$deployed" version)"
printf '%s\n' "$version_output"
if [ -n "${APP_VERSION:-}" ] && ! grep -Fq "$APP_VERSION" <<<"$version_output"; then
    echo "AppImage reports the wrong application version" >&2
    exit 1
fi
APPIMAGE_EXTRACT_AND_RUN=1 "$deployed" profiles

# Execute the same full-window construction smoke used by Flatpak and the
# release gate. This is a finite success/failure test, not a timeout liveness test.
GTK_A11Y=none APPIMAGE_EXTRACT_AND_RUN=1 xvfb-run -a dbus-run-session -- \
    "$deployed" --python-interpreter "$extracted_appdir/usr/share/clamguardian/gtk-smoke.py"

echo "AppImage architecture, runtime, CLI and GTK construction checks passed"
