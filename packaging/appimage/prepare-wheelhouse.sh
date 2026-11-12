#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WHEELHOUSE="$ROOT/packaging/appimage/wheelhouse"
REQUIREMENTS="$(mktemp)"
trap 'rm -f "$REQUIREMENTS"' EXIT
cd "$ROOT"
uv export --frozen --no-dev --no-emit-project --format requirements-txt > "$REQUIREMENTS"
rm -rf "$WHEELHOUSE"
mkdir -p "$WHEELHOUSE"
python -m pip download --require-hashes --only-binary=:all: --dest "$WHEELHOUSE" --requirement "$REQUIREMENTS"
find "$WHEELHOUSE" -maxdepth 1 -type f -name '*.whl' -print -quit | grep -q .
