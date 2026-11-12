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
if [ "$actual_arch" != "$expected_arch" ]; then
  echo "Native runner architecture mismatch: expected $expected_arch, got $actual_arch" >&2
  exit 1
fi

# Verify deployment independently of the original build directory and avoid
# requiring FUSE on CI by using AppImage's extract-and-run mode.
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
deployed="$tmpdir/ClamGuardian.AppImage"
install -m755 "$APPIMAGE" "$deployed"

# Inspect the filesystem before executing it. This catches a missing AppRun
# entrypoint or the Ubuntu compat-runtime linker symlink with a direct error.
extract_root="$tmpdir/extracted"
mkdir -p "$extract_root"
(
  cd "$extract_root"
  "$deployed" --appimage-extract >/dev/null
)
extracted_appdir="$extract_root/squashfs-root"
test -x "$extracted_appdir/AppRun"
test -x "$extracted_appdir/usr/bin/python3"
test -f "$extracted_appdir/lib/python3.12/encodings/__init__.py"
test -s "$extracted_appdir/AppRun.env"
if [ -d "$extracted_appdir/runtime/compat" ]; then
  test -e "$extracted_appdir/runtime/compat/lib64"
  case "$expected_arch" in
    x86_64) linker_name="ld-linux-x86-64.so.2" ;;
    aarch64) linker_name="ld-linux-aarch64.so.1" ;;
  esac
  test -e "$extracted_appdir/runtime/compat/lib64/$linker_name"
fi

version_output="$(APPIMAGE_EXTRACT_AND_RUN=1 "$deployed" version)"
printf '%s\n' "$version_output"
if [ -n "${APP_VERSION:-}" ] && ! grep -Fq "$APP_VERSION" <<<"$version_output"; then
  echo "AppImage reports the wrong application version" >&2
  exit 1
fi
APPIMAGE_EXTRACT_AND_RUN=1 "$deployed" profiles

# The GTK event loop must remain alive until the bounded timeout. A clean
# timeout (124) is expected; early exit or startup errors fail the job.
set +e
GTK_A11Y=none APPIMAGE_EXTRACT_AND_RUN=1 timeout --signal=TERM 20s \
  xvfb-run -a dbus-run-session -- "$deployed" ui
status=$?
set -e
if [ "$status" -ne 124 ]; then
  echo "AppImage GTK startup failed or exited unexpectedly (status=$status)" >&2
  exit 1
fi
echo "AppImage deployment, CLI and GTK startup checks passed"
