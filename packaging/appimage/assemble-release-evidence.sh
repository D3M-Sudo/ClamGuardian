#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 3 ]]; then
    echo "Usage: assemble-release-evidence.sh ARTIFACTS_DIR RELEASE_DIR VERSION" >&2
    exit 2
fi
artifacts_dir="$(realpath "$1")"
release_dir="$(mkdir -p "$2" && realpath "$2")"
version="$3"
[[ "$version" =~ ^[0-9A-Za-z.+_-]+$ ]] || { echo "Invalid release version: $version" >&2; exit 2; }
copy_exactly_one() {
    local pattern="$1" destination="$2" matches
    mapfile -t matches < <(find "$artifacts_dir" -type f -name "$pattern" -print | sort)
    if [[ \${#matches[@]} -ne 1 ]]; then
        echo "Expected exactly one artifact matching $pattern, found \${#matches[@]}" >&2
        return 1
    fi
    cp -- "\${matches[0]}" "$destination"
}
mkdir -p "$release_dir"
for artifact in \
    "ClamGuardian-\${version}-linux-x86_64.flatpak" \
    "ClamGuardian-\${version}-linux-aarch64.flatpak" \
    "ClamGuardian-\${version}-x86_64.AppImage" \
    "ClamGuardian-\${version}-aarch64.AppImage"; do
    copy_exactly_one "$artifact" "$release_dir/$artifact"
done
for architecture in x86_64 aarch64; do
    required_evidence=(
        "aggregate-\${architecture}.spdx.json"
        "aggregate-\${architecture}.cdx.json"
        "appdir.spdx.json"
        "appdir.cdx.json"
        "artifact-\${architecture}.json"
        "schema-validation-\${architecture}.json"
        "native-packages.json"
        "license-evidence-\${architecture}.tar.gz"
    )
    staging="$(mktemp -d "$release_dir/.sbom-\${architecture}.XXXXXX")"
    cleanup() { rm -rf -- "$staging"; }
    trap cleanup EXIT
    for evidence in "\${required_evidence[@]}"; do
        mapfile -t matches < <(find "$artifacts_dir" -type f -path "*/sbom/\${architecture}/\${evidence}" -print | sort)
        if [[ \${#matches[@]} -ne 1 ]]; then
            echo "Expected exactly one \${architecture} SBOM evidence file \${evidence}, found \${#matches[@]}" >&2
            exit 1
        fi
        cp -- "\${matches[0]}" "$staging/$evidence"
    done
    tar -C "$staging" -czf "$release_dir/ClamGuardian-\${version}-sbom-\${architecture}.tar.gz" .
    rm -rf -- "$staging"
    trap - EXIT
done
(
    cd "$release_dir"
    find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\0' | sort -z | xargs -0 sha256sum > SHA256SUMS
    sha256sum --check SHA256SUMS
)
