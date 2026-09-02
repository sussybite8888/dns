#!/bin/bash
#
# Regenerate the per-platform app icons from app_icon.png.
#
# The generated files under assets/icons/ are committed, so this only needs to
# be re-run when app_icon.png changes. It requires macOS (sips, iconutil).

set -e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$ROOT/app_icon.png"
OUT="$ROOT/assets/icons"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [[ ! -f "$SOURCE" ]]; then
    echo "error: $SOURCE not found" >&2
    exit 1
fi

for tool in sips iconutil python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: $tool is required (macOS only)" >&2
        exit 1
    fi
done

SRC_W=$(sips -g pixelWidth "$SOURCE" | awk '/pixelWidth/ {print $2}')
echo "Source: app_icon.png (${SRC_W}x${SRC_W})"
if (( SRC_W < 1024 )); then
    echo "note: source is smaller than 1024x1024, so the largest icons are upscaled."
fi

# resize SIZE OUTPUT_PATH -- square, no alpha (iOS rejects icons with alpha)
resize() {
    sips -s format png -z "$1" "$1" "$SOURCE" --out "$2" >/dev/null
}

mkdir -p "$OUT/macos" "$OUT/windows" "$OUT/ios"

# ---------------------------------------------------------------- macOS .icns
echo "Generating macOS AppIcon.icns..."
ICONSET="$WORK/AppIcon.iconset"
mkdir -p "$ICONSET"
for base in 16 32 128 256 512; do
    resize "$base" "$ICONSET/icon_${base}x${base}.png"
    resize "$((base * 2))" "$ICONSET/icon_${base}x${base}@2x.png"
done
iconutil -c icns "$ICONSET" -o "$OUT/macos/AppIcon.icns"

# -------------------------------------------------------------- Windows .ico
echo "Generating Windows app_icon.ico..."
ICO_ARGS=()
for size in 16 32 48 64 128; do
    resize "$size" "$WORK/ico_$size.png"
    # sips writes 24-bpp BMPs, which make_ico.py widens to 32-bpp DIB entries
    sips -s format bmp "$WORK/ico_$size.png" --out "$WORK/ico_$size.bmp" >/dev/null
    ICO_ARGS+=("$size:$WORK/ico_$size.bmp")
done
resize 256 "$WORK/ico_256.png"   # 256px stays PNG-compressed inside the .ico
ICO_ARGS+=("256:$WORK/ico_256.png")
python3 "$ROOT/scripts/make_ico.py" "$OUT/windows/app_icon.ico" "${ICO_ARGS[@]}"

# ------------------------------------------------------------------ iOS PNGs
# Plain PNGs listed in the Info.plist's CFBundleIconFiles rather than a
# compiled .xcassets: actool needs an installed simulator runtime, which a
# machine that only builds for device does not necessarily have.
echo "Generating iOS icons..."
rm -rf "$OUT/ios"
mkdir -p "$OUT/ios"
# Every pixel size iOS 15+ asks for across iPhone and iPad; the system picks by
# reading each file's dimensions. 1024 is the App Store marketing icon and is
# generated for submission but deliberately left out of the bundle.
for size in 20 29 40 58 60 76 80 87 120 152 167 180 1024; do
    resize "$size" "$OUT/ios/AppIcon-${size}.png"
done

echo ""
echo "Done:"
echo "  macOS   $OUT/macos/AppIcon.icns"
echo "  Windows $OUT/windows/app_icon.ico"
echo "  iOS     $OUT/ios/AppIcon-*.png"
