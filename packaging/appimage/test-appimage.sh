#!/usr/bin/env bash
set -euo pipefail

APPIMAGE="$(realpath "${1:?usage: test-appimage.sh /path/to/ClamGuardian.AppImage /path/to/sbom-dir}")"
SBOM_DIR="$(realpath "${2:?usage: test-appimage.sh /path/to/ClamGuardian.AppImage /path/to/sbom-dir}")"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
test -x "$APPIMAGE"
expected_arch="${APPIMAGE_ARCH:-$(uname -m)}"
actual_arch="$(uname -m)"
file_description="$(file "$APPIMAGE")"

case "$expected_arch" in
    x86_64) grep -Eq 'x86-64|x86_64' <<<"$file_description" ;;
    aarch64) grep -Eq 'ARM aarch64|AArch64' <<<"$file_description" ;;
    *) echo "Unsupported expected architecture: $expected_arch" >&2; exit 1 ;;
esac
test "$actual_arch" = "$expected_arch" || {
    echo "Native runner mismatch: expected $expected_arch, got $actual_arch" >&2
    exit 1
}

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
deployed="$tmpdir/ClamGuardian.AppImage"
install -m755 "$APPIMAGE" "$deployed"

extract_root="$tmpdir/extracted"
mkdir -p "$extract_root"
(cd "$extract_root" && "$deployed" --appimage-extract >/dev/null)
extracted_appdir="$extract_root/squashfs-root"

test -x "$extracted_appdir/AppRun"
test -f "$extracted_appdir/io.github.clamguardian.ClamGuardian.svg"
test -f "$extracted_appdir/usr/share/applications/io.github.clamguardian.ClamGuardian.desktop"
test -f "$extracted_appdir/usr/share/metainfo/io.github.clamguardian.ClamGuardian.appdata.xml"
test -x "$extracted_appdir/usr/bin/python3"
test -x "$extracted_appdir/usr/bin/gdk-pixbuf-query-loaders"
test -f "$extracted_appdir/lib/python3.12/encodings/__init__.py"
test -d "$extracted_appdir/usr/lib/python3/dist-packages/gi"
test -d "$extracted_appdir/usr/lib/girepository-1.0"
test -f "$extracted_appdir/usr/share/clamguardian/gtk-smoke.py"
test -f "$extracted_appdir/usr/share/glib-2.0/schemas/gschemas.compiled"
test -f "$extracted_appdir/etc/ssl/certs/ca-certificates.crt"
test -f "$extracted_appdir/usr/lib/$(/usr/bin/python3.12 -c 'import sysconfig; print(sysconfig.get_config_var("MULTIARCH"))')/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-svg.so"

license_dir="$extracted_appdir/usr/share/licenses/ClamGuardian"
for license_file in GPL-3.0-or-later.txt ClamGuardian-COPYRIGHT.txt components.json runtime-type2.json native-packages.json; do
    test -s "$license_dir/$license_file" || {
        echo "AppImage is missing required license evidence: $license_file" >&2
        exit 1
    }
    if [[ "$license_file" != "native-packages.json" ]]; then
        cmp -s "$ROOT/packaging/appimage/licenses/$license_file" "$license_dir/$license_file" || {
            echo "AppImage license evidence differs from the reviewed source: $license_file" >&2
            exit 1
        }
    fi
done
for runtime_license in \
    AppImage-type2-runtime-MIT.txt musl-COPYRIGHT.txt libfuse-LGPL2.txt \
    squashfuse-LICENSE.txt zstd-LICENSE.txt zlib-LICENSE.txt mimalloc-LICENSE.txt; do
    test -s "$license_dir/third-party/runtime/$runtime_license" || {
        echo "AppImage is missing Type 2 runtime license: $runtime_license" >&2
        exit 1
    }
    cmp -s "$ROOT/packaging/appimage/licenses/third-party/runtime/$runtime_license" \
        "$license_dir/third-party/runtime/$runtime_license" || {
        echo "AppImage Type 2 runtime license differs from verified source: $runtime_license" >&2
        exit 1
    }
done
python3 - "$license_dir/native-packages.json" <<'PYTHON'
import json
import sys
from pathlib import Path
manifest_path = Path(sys.argv[1])
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
if manifest.get("missing_copyright_packages"):
    raise SystemExit("AppImage native package manifest reports missing copyright documents")
if manifest.get("missing_embedded_component_evidence"):
    raise SystemExit("AppImage native package manifest reports missing embedded component evidence")
if not manifest.get("packages"):
    raise SystemExit("AppImage native package manifest is empty")
package_names = {str(item.get("package", "")).split(":", 1)[0] for item in manifest["packages"]}
if "ca-certificates" not in package_names:
    raise SystemExit("AppImage native package inventory does not identify ca-certificates")
if not any(item.get("name") == "libmpdec" for item in manifest.get("embedded_components", [])):
    raise SystemExit("AppImage native package inventory does not identify embedded libmpdec")
for package in manifest["packages"]:
    relative = package.get("copyright_artifact_path")
    if not relative or not (manifest_path.parent / relative).is_file():
        raise SystemExit(f"Missing staged copyright document for {package.get('package')}")
for component in manifest.get("embedded_components", []):
    for evidence in component.get("evidence_paths", []):
        if not (manifest_path.parent / evidence).is_file():
            raise SystemExit(f"Missing embedded component evidence: {evidence}")
components = json.loads((manifest_path.parent / "components.json").read_text(encoding="utf-8"))
for component in components.get("components", []):
    for evidence in component.get("evidence_paths", []):
        if not (manifest_path.parents[4] / evidence).exists():
            raise SystemExit(f"Missing Python wheel license metadata: {evidence}")
runtime = json.loads((manifest_path.parent / "runtime-type2.json").read_text(encoding="utf-8"))
for component in runtime.get("components", []):
    for evidence in component.get("evidence_paths", []):
        if not (manifest_path.parents[4] / evidence).is_file():
            raise SystemExit(f"Missing runtime license evidence: {evidence}")
PYTHON

for pattern in \
    'libgtk-4.so.1*' \
    'libadwaita-1.so.0*' \
    'libsecret-1.so.0*' \
    'libgirepository-*.so.*'; do
    find "$extracted_appdir/usr/lib" -name "$pattern" -print -quit | grep -q . || {
        echo "AppImage is missing bundled runtime library: $pattern" >&2
        exit 1
    }
done

for typelib in Gtk-4.0.typelib Adw-1.typelib Secret-1.typelib; do
    find "$extracted_appdir/usr/lib" -path '*/girepository-1.0/*' -name "$typelib" -print -quit | grep -q . || {
        echo "AppImage is missing GI typelib: $typelib" >&2
        exit 1
    }
done

version_output="$(APPIMAGE_EXTRACT_AND_RUN=1 "$deployed" version)"
printf '%s\n' "$version_output"
if [ -n "${APP_VERSION:-}" ] && ! grep -Fq "$APP_VERSION" <<<"$version_output"; then
    echo "AppImage reports the wrong application version" >&2
    exit 1
fi
APPIMAGE_EXTRACT_AND_RUN=1 "$deployed" profiles

# Execute the same full-window construction smoke used by Flatpak and the
# release gate. This is a finite success/failure test, not a timeout liveness test.
GTK_A11Y=none APPIMAGE_EXTRACT_AND_RUN=1 xvfb-run -a dbus-run-session -- \
    "$deployed" --python-interpreter "$extracted_appdir/usr/share/clamguardian/gtk-smoke.py"

python3 "$ROOT/packaging/appimage/verify-sbom.py" \
    --artifact "$APPIMAGE" \
    --architecture "$expected_arch" \
    --sbom-dir "$SBOM_DIR" \
    --runtime-inventory "$ROOT/packaging/appimage/licenses/runtime-type2.json" \
    --native-inventory "$license_dir/native-packages.json" \
    --appdir-inventory "$license_dir/components.json"
python3 - "$SBOM_DIR/schema-validation-$expected_arch.json" <<'PYTHON'
import json
import sys
from pathlib import Path
report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
documents = report.get("documents", {})
if report.get("schema_validation") != "passed" or len(documents) != 4:
    raise SystemExit("SBOM schema validation report is incomplete or unsuccessful")
if any(item.get("status") != "passed" for item in documents.values()):
    raise SystemExit("SBOM schema validation report contains a non-passing document")
PYTHON

echo "AppImage architecture, runtime, licenses, SBOM, CLI and GTK construction checks passed"
