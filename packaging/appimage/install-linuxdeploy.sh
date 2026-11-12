#!/usr/bin/env bash
set -euo pipefail

: "${APPIMAGE_ARCH:?APPIMAGE_ARCH must be x86_64 or aarch64}"

case "$APPIMAGE_ARCH" in
    x86_64)
        asset="linuxdeploy-x86_64.AppImage"
        expected_sha256="df908b19f1ed1cdafa79508d415aa12d6c56ce4d56d4149aa8c09286718706e5"
        ;;
    aarch64)
        asset="linuxdeploy-aarch64.AppImage"
        expected_sha256="f38e4d7cebf20d8073ec4e00e0a167ac146cd8585fe2f8fe82df27d74f2bd8e1"
        ;;
    *)
        echo "Unsupported linuxdeploy architecture: $APPIMAGE_ARCH" >&2
        exit 1
        ;;
esac

# Upstream currently publishes a continuous asset; the immutable SHA-256 pin
# makes any upstream replacement fail closed until this file is reviewed.
tool_dir="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/linuxdeploy-${APPIMAGE_ARCH}"
binary="$tool_dir/$asset"
url="https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/$asset"
mkdir -p "$tool_dir"

if [ ! -f "$binary" ] || ! printf '%s  %s\n' "$expected_sha256" "$binary" | sha256sum --check --status; then
    tmp="$binary.download"
    curl --fail --location --retry 3 --retry-delay 2 "$url" --output "$tmp"
    printf '%s  %s\n' "$expected_sha256" "$tmp" | sha256sum --check -
    chmod +x "$tmp"
    mv "$tmp" "$binary"
fi

chmod +x "$binary"
export LINUXDEPLOY_BINARY="$binary"
export APPIMAGE_EXTRACT_AND_RUN=1
"$LINUXDEPLOY_BINARY" --help 2>&1 | grep -q -- '--library' || {
    echo "Pinned linuxdeploy binary does not expose the required --library option" >&2
    exit 1
}
