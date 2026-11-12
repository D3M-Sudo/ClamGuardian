#!/usr/bin/env bash
set -euo pipefail

SYFT_VERSION="1.57.1"
APPIMAGE_ARCH="${APPIMAGE_ARCH:?APPIMAGE_ARCH must be x86_64 or aarch64}"
case "$APPIMAGE_ARCH" in
    x86_64) syft_arch="amd64" ;;
    aarch64) syft_arch="arm64" ;;
    *)
        echo "Unsupported Syft architecture: $APPIMAGE_ARCH" >&2
        exit 1
        ;;
esac

SYFT_INSTALL_DIR="${SYFT_INSTALL_DIR:-${RUNNER_TEMP:-/tmp}/syft-${SYFT_VERSION}/bin}"
SYFT_CACHE_DIR="${SYFT_CACHE_DIR:-${RUNNER_TEMP:-/tmp}/syft-${SYFT_VERSION}/cache}"
asset="syft_${SYFT_VERSION}_linux_${syft_arch}.tar.gz"
archive="$SYFT_CACHE_DIR/$asset"
url="https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/${asset}"
checksums="$SYFT_CACHE_DIR/syft_${SYFT_VERSION}_checksums.txt"
checksums_url="https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_checksums.txt"
checksums_sha256="92466b2b1a4695ee908f8a1567f4ff074e0fbb4f34da28463927a2630901fe2c"

mkdir -p "$SYFT_CACHE_DIR" "$SYFT_INSTALL_DIR"
curl --fail --location --silent --show-error "$checksums_url" --output "$checksums"
actual_checksums_sha256="$(sha256sum "$checksums" | cut -d ' ' -f 1)"
if [[ "$actual_checksums_sha256" != "$checksums_sha256" ]]; then
    rm -f "$checksums"
    echo "Syft release checksums file did not match its pinned SHA-256" >&2
    exit 1
fi
curl --fail --location --silent --show-error "$url" --output "$archive"
checksum_line="$(awk -v expected="$asset" '$2 == expected { print }' "$checksums")"
if [[ -z "$checksum_line" ]] || ! printf '%s\n' "$checksum_line" | (cd "$SYFT_CACHE_DIR" && sha256sum --check --status); then
    rm -f "$archive"
    echo "Syft checksum mismatch for $asset" >&2
    exit 1
fi

extract_dir="$SYFT_CACHE_DIR/extracted"
rm -rf "$extract_dir"
mkdir -p "$extract_dir"
tar -xzf "$archive" -C "$extract_dir" syft
install -m 0755 "$extract_dir/syft" "$SYFT_INSTALL_DIR/syft"
"$SYFT_INSTALL_DIR/syft" version | grep -F "$SYFT_VERSION" >/dev/null || {
    echo "Installed Syft binary does not report expected version $SYFT_VERSION" >&2
    exit 1
}
export PATH="$SYFT_INSTALL_DIR:$PATH"
echo "SYFT_BINARY=$SYFT_INSTALL_DIR/syft"
