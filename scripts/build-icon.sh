#!/bin/sh
# Rebuild the bundled macOS icon from the original artwork.
set -eu
cd "$(dirname "$0")/.."
ICON_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tripwire-icon.XXXXXX")"
trap 'rm -rf "$ICON_WORK_DIR"' EXIT HUP INT TERM
ICONSET="$ICON_WORK_DIR/AppIcon.iconset"
mkdir -p "$ICONSET"
for SIZE in 16 32 128 256 512; do
    /usr/bin/sips -z "$SIZE" "$SIZE" assets/branding/AppIcon.png --out "$ICONSET/icon_${SIZE}x${SIZE}.png" > /dev/null
    RETINA_SIZE=$((SIZE * 2))
    /usr/bin/sips -z "$RETINA_SIZE" "$RETINA_SIZE" assets/branding/AppIcon.png --out "$ICONSET/icon_${SIZE}x${SIZE}@2x.png" > /dev/null
done
/usr/bin/iconutil -c icns "$ICONSET" -o Sources/TripWireApp/Resources/AppIcon.icns
printf '%s\n' 'Built Sources/TripWireApp/Resources/AppIcon.icns'
