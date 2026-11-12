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

python3 -m pip install --disable-pip-version-check --only-binary=:all: "jsonschema==4.26.0"
export SBOM_SCHEMA_DIR="$SCHEMA_DIR"
echo "SBOM_SCHEMA_DIR=$SCHEMA_DIR"
