#!/usr/bin/env bash
set -euo pipefail

: "${APPIMAGE_ARCH:?APPIMAGE_ARCH must be x86_64 or aarch64}"

case "$APPIMAGE_ARCH" in
  x86_64)
    asset="appimagetool-x86_64.AppImage"
    expected_sha256="ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0"
    runtime_asset="runtime-x86_64"
    runtime_sha256="2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d"
    ;;
  aarch64)
    asset="appimagetool-aarch64.AppImage"
    expected_sha256="f0837e7448a0c1e4e650a93bb3e85802546e60654ef287576f46c71c126a9158"
    runtime_asset="runtime-aarch64"
    runtime_sha256="00cbdfcf917cc6c0ff6d3347d59e0ca1f7f45a6df1a428a0d6d8a78664d87444"
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
printf '%s  %s\n' "$expected_sha256" "$APPIMAGETOOL_DIR/$asset" | sha256sum --check -

chmod +x "$APPIMAGETOOL_DIR/$asset"

# Use the maintained type2-runtime, whose embedded SquashFS reader supports
# the Zstandard compression emitted by appimagetool 1.9.1. The older
# AppImageKit runtime downloaded by appimage-builder cannot read this format.
runtime_url="https://github.com/AppImage/type2-runtime/releases/download/20251108/$runtime_asset"
curl --fail --location --retry 3 "$runtime_url" --output "$APPIMAGETOOL_DIR/$runtime_asset"
printf '%s  %s\n' "$expected_sha256" "$APPIMAGETOOL_DIR/$asset" | sha256sum --check -
chmod +x "$APPIMAGETOOL_DIR/$runtime_asset"

# appimage-builder passes its own legacy --runtime-file. Replace it with the
# pinned type2-runtime while preserving every other argument.
cat > "$APPIMAGETOOL_DIR/appimagetool" <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
args=()
skip_next=0
for arg in "$@"; do
  if [ "$skip_next" -eq 1 ]; then
    skip_next=0
    continue
  fi
  if [ "$arg" = "--runtime-file" ]; then
    skip_next=1
    continue
  fi
  args+=("$arg")
done
if [ "$skip_next" -eq 1 ]; then
  echo "appimagetool received --runtime-file without a value" >&2
  exit 2
fi
exec env APPIMAGE_EXTRACT_AND_RUN=1 "$APPIMAGETOOL_DIR_PLACEHOLDER/$ASSET_PLACEHOLDER" \
  --runtime-file "$APPIMAGETOOL_DIR_PLACEHOLDER/$RUNTIME_ASSET_PLACEHOLDER" "${args[@]}"
WRAPPER
sed -i \
  -e "s|APPIMAGETOOL_DIR_PLACEHOLDER|$APPIMAGETOOL_DIR|g" \
  -e "s|ASSET_PLACEHOLDER|$asset|g" \
  -e "s|RUNTIME_ASSET_PLACEHOLDER|$runtime_asset|g" \
  "$APPIMAGETOOL_DIR/appimagetool"
chmod +x "$APPIMAGETOOL_DIR/appimagetool"

export APPIMAGE_EXTRACT_AND_RUN=1
export PATH="$APPIMAGETOOL_DIR:$PATH"
command -v appimagetool
appimagetool --version
