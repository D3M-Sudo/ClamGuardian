#!/usr/bin/env bash
set -euo pipefail

DESTINATION="$(realpath -m "${1:?usage: collect-runtime-source-bundle.sh DESTINATION ARCHITECTURE}")"
ARCHITECTURE="${2:?usage: collect-runtime-source-bundle.sh DESTINATION ARCHITECTURE}"
case "$ARCHITECTURE" in x86_64|aarch64) ;; *) echo "unsupported architecture: $ARCHITECTURE" >&2; exit 2 ;; esac

RUNTIME_COMMIT="dd6cebedcbddde9c82f89b011e8e1d40b6e43868"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
ROOT="$WORK/runtime-source-bundle-$ARCHITECTURE"
mkdir -p "$ROOT/sources" "$ROOT/build-inputs/type2-runtime" "$ROOT/build-inputs/alpine-3.21"

fetch() {
    local url="$1" output="$2"
    curl --fail --location --silent --show-error "$url" --output "$output"
}

verify_sha256() {
    local file="$1" expected="$2"
    printf '%s  %s\n' "$expected" "$file" | sha256sum --check --status
}

verify_sha512() {
    local file="$1" expected="$2"
    printf '%s  %s\n' "$expected" "$file" | sha512sum --check --status
}

# The exact Type 2 runtime source revision used by this project.
git clone --quiet --filter=blob:none --no-checkout https://github.com/AppImage/type2-runtime.git "$WORK/type2-runtime"
git -C "$WORK/type2-runtime" checkout --quiet --detach "$RUNTIME_COMMIT"
test "$(git -C "$WORK/type2-runtime" rev-parse HEAD)" = "$RUNTIME_COMMIT"
git -C "$WORK/type2-runtime" archive --format=tar "$RUNTIME_COMMIT" | gzip -n > "$ROOT/sources/AppImage-type2-runtime-$RUNTIME_COMMIT.tar.gz"

# Exact libfuse and squashfuse source archives from the pinned upstream recipe.
fetch "https://github.com/libfuse/libfuse/releases/download/fuse-3.15.0/fuse-3.15.0.tar.xz" "$ROOT/sources/fuse-3.15.0.tar.xz"
verify_sha256 "$ROOT/sources/fuse-3.15.0.tar.xz" "70589cfd5e1cff7ccd6ac91c86c01be340b227285c5e200baa284e401eea2ca0"
fetch "https://github.com/vasi/squashfuse/archive/0.5.2.tar.gz" "$ROOT/sources/squashfuse-0.5.2.tar.gz"
verify_sha256 "$ROOT/sources/squashfuse-0.5.2.tar.gz" "db0238c5981dabbd80ee09ae15387f390091668ca060a7bc38047912491443d3"

# Static runtime dependencies. Each archive is checked against the Alpine 3.21
# source-package checksum; these are source snapshots, not claims about the
# exact APK revision installed by the historical upstream build.
fetch "https://github.com/facebook/zstd/archive/v1.5.6.tar.gz" "$ROOT/sources/zstd-1.5.6.tar.gz"
verify_sha512 "$ROOT/sources/zstd-1.5.6.tar.gz" "ca12dffd86618ca008e1ecc79056c1129cb4e61668bf13a3cd5b2fa5c93bc9c92c80f64c1870c68b9c20009d9b3a834eac70db72242d5106125a1c53cccf8de8"
fetch "https://zlib.net/fossils/zlib-1.3.1.tar.gz" "$ROOT/sources/zlib-1.3.1.tar.gz"
verify_sha512 "$ROOT/sources/zlib-1.3.1.tar.gz" "580677aad97093829090d4b605ac81c50327e74a6c2de0b85dd2e8525553f3ddde17556ea46f8f007f89e435493c9a20bc997d1ef1c1c2c23274528e3c46b94f"
fetch "https://musl.libc.org/releases/musl-1.2.5.tar.gz" "$ROOT/sources/musl-1.2.5.tar.gz"
verify_sha512 "$ROOT/sources/musl-1.2.5.tar.gz" "7bb7f7833923cd69c7a1a9b8a5f1784bfd5289663eb6061dcd43d583e45987df8a68a1be05d75cc1c88a3f5b610653d1a70f4a9cff4d8f7fd41ae73ee058c17c"
fetch "https://github.com/microsoft/mimalloc/archive/v2.1.7/mimalloc-2.1.7.tar.gz" "$ROOT/sources/mimalloc-2.1.7-candidate.tar.gz"
verify_sha512 "$ROOT/sources/mimalloc-2.1.7-candidate.tar.gz" "4e30976758015c76a146acc1bfc8501e2e5c61b81db77d253de0d58a8edef987669243f232210667b32ef8da3a33286642acb56ba526fd24c4ba925b44403730"

# Preserve the exact build recipe and applied libfuse patch.
cp "$WORK/type2-runtime/src/runtime/Makefile" "$ROOT/build-inputs/type2-runtime/"
cp "$WORK/type2-runtime/scripts/common/install-dependencies.sh" "$ROOT/build-inputs/type2-runtime/"
cp "$WORK/type2-runtime/scripts/docker/Dockerfile" "$ROOT/build-inputs/type2-runtime/"
cp -a "$WORK/type2-runtime/patches" "$ROOT/build-inputs/type2-runtime/"
for item in zstd zlib musl; do
    fetch "https://raw.githubusercontent.com/alpinelinux/aports/v3.21.0/main/$item/APKBUILD" "$ROOT/build-inputs/alpine-3.21/$item.APKBUILD"
done
fetch "https://raw.githubusercontent.com/alpinelinux/aports/v3.21.0/community/mimalloc2/APKBUILD" "$ROOT/build-inputs/alpine-3.21/mimalloc2.APKBUILD"

cat > "$ROOT/README-RELINK.md" <<'EOF'
# AppImage Type 2 runtime source and relink materials

This archive preserves the pinned AppImage/type2-runtime source revision,
the exact libfuse 3.15.0 source archive and its applied mount.c patch,
squashfuse 0.5.2, the runtime Makefile, upstream install script and Dockerfile,
plus checksummed source snapshots for the Alpine 3.21 static runtime
dependencies (zstd, zlib, musl and a mimalloc 2.1.7 candidate).

## Reconstructing the Type 2 runtime

1. Extract the archive and inspect `build-inputs/type2-runtime`.
2. Extract `sources/fuse-3.15.0.tar.xz`, apply
   `patches/libfuse/mount.c.diff` with `patch -p1`, then build libfuse
   with Meson using `--default-library static`.
3. Build squashfuse 0.5.2 with the static-link flags from the preserved
   upstream `install-dependencies.sh`.
4. Build/install the static dependencies from the supplied source snapshots,
   then use the preserved runtime Makefile to relink the runtime.
5. The Type 2 runtime source archive is pinned to
   `$RUNTIME_COMMIT`; compare its source against the archived build inputs.

## Evidence limitation — NOT A LEGAL COMPLIANCE CONCLUSION

The historical upstream Dockerfile requested `mimalloc-dev`, but the exact
provider selected and installed APK revision were not retained in the
upstream build logs. Alpine 3.21's `mimalloc2-dev` source recipe identifies
2.1.7 as a candidate, not as proof of the version actually linked into the
published runtime. This archive includes that candidate source so a rebuild
can be attempted, but it does not establish binary/source identity for
mimalloc. The exact installed APK revisions for other dependencies are also
not preserved. Therefore this archive is a source-and-rebuild evidence
package, not a representation that all LGPL-2.1 §6 obligations have been
conclusively satisfied. Keep the compliance status blocked until the missing
historical provenance and the practical relink procedure have been reviewed.
EOF
sed -i "s/\$RUNTIME_COMMIT/$RUNTIME_COMMIT/g" "$ROOT/README-RELINK.md"

cat > "$ROOT/source-manifest.txt" <<EOF
architecture=$ARCHITECTURE
type2_runtime_commit=$RUNTIME_COMMIT
libfuse_version=3.15.0
libfuse_source_sha256=70589cfd5e1cff7ccd6ac91c86c01be340b227285c5e200baa284e401eea2ca0
squashfuse_version=0.5.2
squashfuse_source_sha256=db0238c5981dabbd80ee09ae15387f390091668ca060a7bc38047912491443d3
zstd_source_version=1.5.6
zlib_source_version=1.3.1
musl_source_version=1.2.5
mimalloc_source_candidate=2.1.7
mimalloc_linked_version=UNKNOWN
mimalloc_installed_apk_revision=UNKNOWN
lgpl_compliance_status=NOT ESTABLISHED BY THIS ARCHIVE
EOF

(
  cd "$ROOT"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)
mkdir -p "$DESTINATION"
tar -C "$WORK" -czf "$DESTINATION/runtime-source-bundle-$ARCHITECTURE.tar.gz" "runtime-source-bundle-$ARCHITECTURE"
sha256sum "$DESTINATION/runtime-source-bundle-$ARCHITECTURE.tar.gz" > "$DESTINATION/runtime-source-bundle-$ARCHITECTURE.tar.gz.sha256"
echo "Created source/relink evidence bundle: $DESTINATION/runtime-source-bundle-$ARCHITECTURE.tar.gz"
