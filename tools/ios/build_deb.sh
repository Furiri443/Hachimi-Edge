#!/usr/bin/env bash
# tools/ios/build_deb.sh
# Package libhachimi.dylib into .deb for rootful & rootless jailbreak
#
# Usage:
#   ./tools/ios/build_deb.sh <libhachimi.dylib> [version]
#
# If version is omitted, it is read from Cargo.toml.
# Output: hachimi_<version>_rootful.deb and hachimi_<version>_rootless.deb
set -euo pipefail

DYLIB="${1:?Usage: $0 <libhachimi.dylib> [version]}"
VERSION="${2:-}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEMPLATE_DIR="$SCRIPT_DIR/deb"
OUTPUT_DIR="${OUTPUT_DIR:-.}"

# ── Resolve version from Cargo.toml if not provided ──────────────
if [[ -z "$VERSION" ]]; then
    CARGO_TOML="$SCRIPT_DIR/../../Cargo.toml"
    if [[ -f "$CARGO_TOML" ]]; then
        VERSION=$(awk '/^\[package\]/{flag=1} flag && /^version/{print $3; exit}' "$CARGO_TOML" | tr -d '"')
    fi
    if [[ -z "$VERSION" ]]; then
        echo "ERROR: Could not determine version. Pass it as 2nd argument."
        exit 1
    fi
fi

echo "[deb] Version: $VERSION"
echo "[deb] Dylib:   $DYLIB"

# ── Filter plist (configurable via BUNDLE_FILTER env) ─────────────
BUNDLE_FILTER="${BUNDLE_FILTER:-jp.co.cygames.umamusume,app.papaya2933.cheetah1054,com.komoe.kmumamusumegp,com.komoe.umamusumeofficial,com.kakaogames.umamusume,com.bilibili.umamusu,com.cygames.umamusume}"
FILTER_PLIST=$(mktemp)

# Build filter plist with multiple bundle support
BUNDLES_STR=""
IFS=',' read -ra BUNDLE_ARRAY <<< "$BUNDLE_FILTER"
for b in "${BUNDLE_ARRAY[@]}"; do
    b=$(echo "$b" | xargs)  # trim whitespace
    BUNDLES_STR="${BUNDLES_STR}\"${b}\", "
done
echo "{ Filter = { Bundles = ( ${BUNDLES_STR%,*} ); }; }" > "$FILTER_PLIST"
echo "[deb] Filter:  $(cat "$FILTER_PLIST")"

# ── Build function ────────────────────────────────────────────────
build_deb() {
    local VARIANT="$1"   # rootful or rootless
    local BASE_PATH="$2" # "" for rootful, "var/jb" for rootless

    local STAGE=$(mktemp -d)
    local TWEAK_DIR="$STAGE/${BASE_PATH:+$BASE_PATH/}Library/MobileSubstrate/DynamicLibraries"

    # 1. Create directory structure
    mkdir -p "$STAGE/DEBIAN"
    mkdir -p "$TWEAK_DIR"

    # 2. Copy control file and substitute version
    sed "s/\${VERSION}/$VERSION/g" "$TEMPLATE_DIR/$VARIANT/DEBIAN/control" > "$STAGE/DEBIAN/control"

    # 3. Copy dylib + filter plist
    cp "$DYLIB" "$TWEAK_DIR/libhachimi.dylib"
    cp "$FILTER_PLIST" "$TWEAK_DIR/hachimi.plist"

    # 4. Fix permissions (dpkg-deb requires specific perms)
    find "$STAGE" -type d -exec chmod 755 {} \;
    chmod 644 "$STAGE/DEBIAN/control"
    chmod 755 "$TWEAK_DIR/libhachimi.dylib"
    chmod 644 "$TWEAK_DIR/hachimi.plist"

    # 5. Build .deb
    local DEB_FILE="$OUTPUT_DIR/hachimi_${VERSION}_${VARIANT}.deb"
    dpkg-deb -Zxz --build "$STAGE" "$DEB_FILE"

    echo "[deb] Built: $DEB_FILE ($(du -sh "$DEB_FILE" | cut -f1))"

    # Cleanup
    rm -rf "$STAGE"
}

# ── Build both variants ───────────────────────────────────────────
echo ""
echo "═══ Building Rootful .deb ═══"
build_deb "rootful" ""

echo ""
echo "═══ Building Rootless .deb ═══"
build_deb "rootless" "var/jb"

# Cleanup
rm -f "$FILTER_PLIST"

echo ""
echo "[deb] Done! Output files:"
ls -lh "$OUTPUT_DIR"/hachimi_${VERSION}_*.deb
