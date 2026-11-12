#!/usr/bin/env bash
set -euo pipefail

: "${APPIMAGE_ARCH:?APPIMAGE_ARCH must be x86_64 or aarch64}"

case "$APPIMAGE_ARCH" in
  x86_64)
    asset="appimagetool-x86_64.AppImage"
    expected_sha256="ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0"
    ;;
  aarch64)
    asset="appimagetool-aarch64.AppImage"
    expected_sha256="f0837e7448a0c1e4e650a93bb3e85802546e60654ef287576f46c71c126a9158"
    ;;
  *)
    echo "Unsupported AppImage architecture: $APPIMAGE_ARCH" >&2
    exit 1
    ;;
esac

# appimage-builder 1.0.0 invokes appimagetool as an external command.
# Pin the official AppImage/appimagetool 1.9.1 asset and verify its digest.
APPIMAGETOOL_DIR="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/appimagetool-${APPIMAGE_ARCH}"
mkdir -p "$APPIMAGETOOL_DIR"
curl --fail --location --retry 3 \
  "https://github.com/AppImage/appimagetool/releases/download/1.9.1/$asset" \
  --output "$APPIMAGETOOL_DIR/$asset"
printf '%s  %s\\n' "$expected_sha256" "$APPIMAGETOOL_DIR/$asset" | sha256sum --check -

chmod +x "$APPIMAGETOOL_DIR/$asset"

# Extract the AppImage rather than relying on host FUSE availability.
# This is the upstream-documented workaround for running appimagetool in CI.
sed -i 's|AI\\x02|\\x00\\x00\\x00|' "$APPIMAGETOOL_DIR/$asset"
(
  cd "$APPIMAGETOOL_DIR"
  "./$asset" --appimage-extract
)
test -x "$APPIMAGETOOL_DIR/squashfs-root/AppRun"
ln -sfn "$APPIMAGETOOL_DIR/squashfs-root/AppRun" "$APPIMAGETOOL_DIR/appimagetool"
export PATH="$APPIMAGETOOL_DIR:$PATH"
command -v appimagetool
appimagetool --version
