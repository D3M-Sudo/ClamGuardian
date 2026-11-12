#!/usr/bin/env bash
set -euo pipefail

DESTINATION="$(realpath -m "${1:?usage: collect-runtime-licenses.sh DESTINATION}")"
mkdir -p "$DESTINATION"

fetch_verified() {
    local name="$1"
    local url="$2"
    local expected_blob_sha="$3"
    local destination="$DESTINATION/$name"
    local temporary="$destination.download"
    curl --fail --location --silent --show-error "$url" --output "$temporary"
    python3 - "$temporary" "$expected_blob_sha" <<'PYTHON'
import hashlib
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
content = path.read_bytes()
actual = hashlib.sha1(f"blob {len(content)}\0".encode() + content).hexdigest()
if actual != sys.argv[2]:
    raise SystemExit(f"upstream license Git blob SHA mismatch: expected {sys.argv[2]}, got {actual}")
PYTHON
    mv "$temporary" "$destination"
}

fetch_verified "AppImage-type2-runtime-MIT.txt" \
    "https://raw.githubusercontent.com/AppImage/type2-runtime/dd6cebedcbddde9c82f89b011e8e1d40b6e43868/LICENSE" \
    "a9fd00b042f392357a84fd81b7789976a53f5b4e"
fetch_verified "musl-COPYRIGHT.txt" \
    "https://raw.githubusercontent.com/ifduyue/musl/v1.2.5/COPYRIGHT" \
    "c1628e9ac84f927fe791124ec172fb61c760bb9b"
fetch_verified "libfuse-LGPL2.txt" \
    "https://raw.githubusercontent.com/libfuse/libfuse/fuse-3.15.0/LGPL2.txt" \
    "4362b49151d7b34ef83b3067a8f9c9f877d72a0e"
fetch_verified "squashfuse-LICENSE.txt" \
    "https://raw.githubusercontent.com/vasi/squashfuse/0.5.2/LICENSE" \
    "2c821bbaa662c7e863424b0523f032b77ab75d87"
fetch_verified "zstd-LICENSE.txt" \
    "https://raw.githubusercontent.com/meta/zstd/v1.5.6/LICENSE" \
    "75800288cc243f164b9d130f125e2ffae28f8e39"
fetch_verified "zlib-LICENSE.txt" \
    "https://raw.githubusercontent.com/madler/zlib/v1.3.1/LICENSE" \
    "ab8ee6f71428c3e4646b12b64ad387cde33462e5"
fetch_verified "mimalloc-LICENSE.txt" \
    "https://raw.githubusercontent.com/microsoft/mimalloc/v2.2.3/LICENSE" \
    "53315ebee557ac22f3396ea1781df0440c26bb15"

echo "Verified and collected seven AppImage Type 2 runtime license documents"
