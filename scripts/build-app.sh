#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
swift build -c release
if [ "$#" -ne 0 ]; then
    printf '%s\n' 'TripWire uses one canonical app: dist/TripWire.app. No alternate app output directories.' >&2
    exit 2
fi
OUTPUT_DIR="dist"
APP="$OUTPUT_DIR/TripWire.app"
mkdir -p "$APP/Contents/MacOS"
mkdir -p "$APP/Contents/Resources"
cp .build/release/TripWireApp "$APP/Contents/MacOS/TripWireApp"
cp -R .build/release/TripWire_TripWireApp.bundle "$APP/Contents/Resources/"
cp Sources/TripWireApp/Resources/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
cp .build/release/tripwire "$OUTPUT_DIR/tripwire"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>local.tripwire.watchdog</string>
<key>CFBundleName</key><string>TripWire</string>
<key>CFBundleDisplayName</key><string>TripWire</string>
<key>CFBundleExecutable</key><string>TripWireApp</string>
<key>CFBundleIconFile</key><string>AppIcon</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
/usr/bin/codesign --force --sign - "$APP"
printf '%s\n' "Built $APP and $OUTPUT_DIR/tripwire. Local ad-hoc signature; no entitlements, installation or auto-launch."
