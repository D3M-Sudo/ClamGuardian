#!/usr/bin/env bash
set -euo pipefail
APPIMAGE="$(realpath "\${1:?usage: test-appimage.sh /path/to/ClamGuardian.AppImage}")"
test -x "$APPIMAGE"
expected_arch="\${APPIMAGE_ARCH:-$(uname -m)}"
actual_arch="$(uname -m)"
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
APPIMAGE_EXTRACT_AND_RUN=1 "$deployed" version
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
