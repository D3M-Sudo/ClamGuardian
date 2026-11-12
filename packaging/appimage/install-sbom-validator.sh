#!/usr/bin/env bash
set -euo pipefail

SCHEMA_DIR="${SBOM_SCHEMA_DIR:-${RUNNER_TEMP:-/tmp}/clamguardian-sbom-schemas}"
mkdir -p "$SCHEMA_DIR"

fetch_schema() {
    local url="$1"
    local expected_blob_sha="$2"
    local destination="$3"
    local temporary="$destination.download"
    curl --fail --location --silent --show-error "$url" --output "$temporary"
    python3 - "$temporary" "$expected_blob_sha" <<'PYTHON'
import hashlib
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
content = path.read_bytes()
header = f"blob {len(content)}\0".encode()
actual = hashlib.sha1(header + content).hexdigest()
if actual != sys.argv[2]:
    raise SystemExit(f"schema Git blob SHA mismatch: expected {sys.argv[2]}, got {actual}")
PYTHON
    mv "$temporary" "$destination"
}

fetch_schema \
    "https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json" \
    "ee61e6686e885f8139c132647fd0b4f483b8fb81" \
    "$SCHEMA_DIR/spdx-schema-2.3.json"
fetch_schema \
    "https://raw.githubusercontent.com/CycloneDX/specification/6470e34ef83f915868ece48934cff52e10c9eb49/schema/bom-1.6.schema.json" \
    "b6c096a999d6ee9e408a9c3ae6c6227d6981c9ba" \
    "$SCHEMA_DIR/cyclonedx-bom-1.6.schema.json"

fetch_schema \
    "https://raw.githubusercontent.com/spdx/license-list-data/31ba1a50e5397e00a304dbadc76531740e89ee48/json/licenses.json" \
    "79ca1b1f6792d599d4fc680782e1f81f5923b636" \
    "$SCHEMA_DIR/spdx-3.29.0-licenses.json"
fetch_schema \
    "https://raw.githubusercontent.com/spdx/license-list-data/31ba1a50e5397e00a304dbadc76531740e89ee48/json/exceptions.json" \
    "ff15183baf7105f9b5747539950018bec7e43ada" \
    "$SCHEMA_DIR/spdx-3.29.0-exceptions.json"

python3 -m pip install --disable-pip-version-check --only-binary=:all: "jsonschema==4.26.0"
export SBOM_SCHEMA_DIR="$SCHEMA_DIR"
echo "SBOM_SCHEMA_DIR=$SCHEMA_DIR"
