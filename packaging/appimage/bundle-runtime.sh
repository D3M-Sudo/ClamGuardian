#!/usr/bin/env bash
set -euo pipefail

APPDIR="$(realpath "${1:?usage: bundle-runtime.sh /path/to/AppDir}")"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
: "${APPIMAGE_ARCH:?APPIMAGE_ARCH must be x86_64 or aarch64}"

MULTIARCH="$(/usr/bin/python3.12 -c 'import sysconfig; print(sysconfig.get_config_var("MULTIARCH"))')"
LIBDIR="/usr/lib/$MULTIARCH"
GIR_SOURCE="$LIBDIR/girepository-1.0"
PIXBUF_SOURCE="$LIBDIR/gdk-pixbuf-2.0/2.10.0/loaders"
QUERY_LOADERS_SOURCE="$LIBDIR/gdk-pixbuf-2.0/gdk-pixbuf-query-loaders"

copy_tree() {
    local source="$1"
    local destination="$2"
    test -d "$source" || { echo "Required runtime directory is missing: $source" >&2; exit 1; }
    mkdir -p "$destination"
    cp -a "$source/." "$destination/"
}

copy_tree_if_present() {
    local source="$1"
    local destination="$2"
    if [ -d "$source" ]; then
        mkdir -p "$destination"
        cp -a "$source/." "$destination/"
    fi
}

# PyGObject and pycairo are supplied by Ubuntu's native Python 3.12 packages.
# Their CPython ABI matches the interpreter copied by build-appimage.sh.
for package in gi cairo; do
    copy_tree "/usr/lib/python3/dist-packages/$package" \
        "$APPDIR/usr/lib/python3/dist-packages/$package"
done
find "$APPDIR/usr/lib/python3/dist-packages" -type d -name __pycache__ -prune -exec rm -rf {} +

# GI typelibs are data, not ELF dependencies, so linuxdeploy cannot discover
# them. Bundle the repository explicitly for GTK4, Libadwaita and Secret.
copy_tree "$GIR_SOURCE" "$APPDIR/usr/lib/girepository-1.0"
copy_tree_if_present "/usr/lib/girepository-1.0" "$APPDIR/usr/lib/girepository-1.0"

# GTK/Adwaita resources, GIO modules and GSettings schemas are runtime data.
for share in \
    glib-2.0/schemas \
    gtk-4.0 \
    libadwaita-1 \
    icons/Adwaita \
    icons/hicolor \
    themes/Adwaita; do
    copy_tree_if_present "/usr/share/$share" "$APPDIR/usr/share/$share"
done
copy_tree_if_present "$LIBDIR/gio/modules" "$APPDIR/usr/lib/$MULTIARCH/gio/modules"
glib-compile-schemas "$APPDIR/usr/share/glib-2.0/schemas"

# GdkPixbuf's loader cache contains absolute module paths. AppRun regenerates
# it at launch against the mounted AppDir, so copy the loaders and query tool.
copy_tree "$PIXBUF_SOURCE" \
    "$APPDIR/usr/lib/$MULTIARCH/gdk-pixbuf-2.0/2.10.0/loaders"
test -x "$QUERY_LOADERS_SOURCE"
install -Dm755 "$QUERY_LOADERS_SOURCE" "$APPDIR/usr/bin/gdk-pixbuf-query-loaders"
test -f "$APPDIR/usr/lib/$MULTIARCH/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-svg.so"

# TLS uses the host-independent CA bundle; do not rely on the host's /etc path.
install -Dm644 /etc/ssl/certs/ca-certificates.crt \
    "$APPDIR/etc/ssl/certs/ca-certificates.crt"

# CPython's python.o is a static-link input, not a runtime object. linuxdeploy
# cannot patch it (patchelf reports "wrong ELF type"), so omit it from AppDir.
for static_object in "$APPDIR"/usr/lib/python3.12/config-*/python.o; do
    if [ -f "$static_object" ]; then
        rm -f "$static_object"
    fi
done

# linuxdeploy is pinned per native architecture and verifies its SHA-256 before
# execution. No appimage-builder source patching or generated AppRun runtime.
# Its default dependency resolver excludes host glibc and graphics drivers.
# Explicit roots cover libraries loaded through GI typelibs/dlopen; scanning
# every ELF module also covers Python extension modules and pixbuf loaders.
# shellcheck source=packaging/appimage/install-linuxdeploy.sh
. "$ROOT/packaging/appimage/install-linuxdeploy.sh"

args=(--appdir "$APPDIR"
      --desktop-file "$APPDIR/usr/share/applications/io.github.clamguardian.ClamGuardian.desktop"
      --custom-apprun "$ROOT/packaging/appimage/AppRun"
      --executable "$APPDIR/usr/bin/python3.12"
      --executable "$APPDIR/usr/bin/gdk-pixbuf-query-loaders")

find_shared_library() {
    local soname="$1"
    local path
    path="$(ldconfig -p | awk -v name="$soname" '$1 == name { print $NF; exit }')"
    test -n "$path" || { echo "Required shared library is missing: $soname" >&2; exit 1; }
    printf '%s\n' "$path"
}

for soname in \
    libgtk-4.so.1 \
    libadwaita-1.so.0 \
    libsecret-1.so.0 \
    libgdk_pixbuf-2.0.so.0 \
    librsvg-2.so.2; do
    args+=(--library "$(find_shared_library "$soname")")
done

while IFS= read -r girepository_library; do
    args+=(--library "$girepository_library")
done < <(ldconfig -p | awk '$1 ~ /^libgirepository-/ { print $NF }' | sort -u)

mapfile -d '' -t elf_modules < <(
    find "$APPDIR" -type f \( -name '*.so' -o -name '*.so.*' \) -print0
)
for module in "${elf_modules[@]}"; do
    if file -b "$module" | grep -q '^ELF '; then
        args+=(--library "$module")
    fi
done

APPIMAGE_EXTRACT_AND_RUN=1 "$LINUXDEPLOY_BINARY" "${args[@]}"

# Fail if any ELF dependency remains unresolved inside the assembled AppDir.
for elf in "$APPDIR/usr/bin/python3.12" "$APPDIR/usr/bin/gdk-pixbuf-query-loaders" "${elf_modules[@]}"; do
    [ -f "$elf" ] || continue
    file -b "$elf" | grep -q '^ELF ' || continue
    output="$(LD_LIBRARY_PATH="$APPDIR/usr/lib:$APPDIR/usr/lib/$MULTIARCH" ldd "$elf" 2>&1 || true)"
    if grep -q 'not found' <<<"$output"; then
        echo "Unresolved AppImage dependency in $elf:" >&2
        printf '%s\n' "$output" >&2
        exit 1
    fi
done

# Required shared libraries and typelibs must be present in the final AppDir.
for pattern in \
    'libgtk-4.so.1*' \
    'libadwaita-1.so.0*' \
    'libsecret-1.so.0*' \
    'libgirepository-*.so.*'; do
    find "$APPDIR/usr/lib" -name "$pattern" -print -quit | grep -q . || {
        echo "linuxdeploy did not bundle required runtime library: $pattern" >&2
        exit 1
    }
done

for typelib in Gtk-4.0.typelib Adw-1.typelib Secret-1.typelib; do
    find "$APPDIR/usr/lib" -path '*/girepository-1.0/*' -name "$typelib" -print -quit | grep -q . || {
        echo "Missing required GI typelib: $typelib" >&2
        exit 1
    }
done

echo "Bundled GTK4, Libadwaita, Secret and Python ELF dependencies for $APPIMAGE_ARCH"
