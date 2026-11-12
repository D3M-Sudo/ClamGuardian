#!/usr/bin/env bash
set -euo pipefail
APPIMAGE="$(realpath "${1:?usage: test-appimage.sh /path/to/ClamGuardian.AppImage}")"
test -x "$APPIMAGE"
"$APPIMAGE" version
"$APPIMAGE" profiles
APPIMAGE_EXTRACT_AND_RUN=1 "$APPIMAGE" version
set +e
GTK_A11Y=none APPIMAGE_EXTRACT_AND_RUN=1 timeout --signal=TERM 20s xvfb-run -a dbus-run-session -- "$APPIMAGE" ui
status=$?
set -e
if [ "$status" -ne 124 ]; then echo "AppImage GUI startup failed ($status)" >&2; exit 1; fi
echo "AppImage CLI and GTK startup checks passed"
