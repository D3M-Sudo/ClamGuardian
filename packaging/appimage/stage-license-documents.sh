#!/usr/bin/env bash
set -euo pipefail

LICENSE_SOURCE="$(realpath "${1:?usage: stage-license-documents.sh LICENSE_SOURCE APPDIR}")"
APPDIR="$(realpath -m "${2:?usage: stage-license-documents.sh LICENSE_SOURCE APPDIR}")"
LICENSE_DEST="$APPDIR/usr/share/licenses/ClamGuardian"

required=(
    GPL-3.0-or-later.txt
    components.json
    runtime-type2.json
)
for filename in "${required[@]}"; do
    if [[ ! -f "$LICENSE_SOURCE/$filename" ]]; then
        echo "Required license evidence is missing: $LICENSE_SOURCE/$filename" >&2
        exit 1
    fi
done

while IFS= read -r -d '' source_file; do
    relative_path="${source_file#"$LICENSE_SOURCE"/}"
    destination="$LICENSE_DEST/$relative_path"
    mkdir -p "$(dirname "$destination")"
    if [[ -e "$destination" ]]; then
        if ! cmp -s "$source_file" "$destination"; then
            echo "Refusing to overwrite different license evidence: $destination" >&2
            exit 1
        fi
        continue
    fi
    install -m 0644 "$source_file" "$destination"
done < <(find "$LICENSE_SOURCE" -type f -print0 | sort -z)

echo "Staged project license and AppImage component inventories in $LICENSE_DEST"
