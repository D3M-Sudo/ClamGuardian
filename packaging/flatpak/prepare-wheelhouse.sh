#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "\${BASH_SOURCE[0]}")/../.." && pwd)"
WHEELHOUSE="$ROOT/packaging/flatpak/wheelhouse"
REQUIREMENTS="$(mktemp)"
trap 'rm -f "$REQUIREMENTS"' EXIT
command -v uv >/dev/null 2>&1 || { echo "uv is required" >&2; exit 1; }
rm -rf "$WHEELHOUSE"
mkdir -p "$WHEELHOUSE"
cd "$ROOT"
uv export --frozen --no-dev --no-emit-project --format requirements-txt > "$REQUIREMENTS"
python -m pip download --require-hashes --only-binary=:all: --dest "$WHEELHOUSE" --requirement "$REQUIREMENTS"
find "$WHEELHOUSE" -maxdepth 1 -type f -name '*.whl' -print -quit | grep -q . || { echo "Empty runtime wheelhouse" >&2; exit 1; }
echo "Prepared $(find "$WHEELHOUSE" -maxdepth 1 -type f -name '*.whl' | wc -l) native runtime wheels"
