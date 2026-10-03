#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
[ "$(uname -s)" = Linux ] || { printf '%s\n' 'Run this script on Linux.' >&2; exit 2; }
build_dir="${TRIPWIRE_BUILD_PATH:-.build}"
swift build --scratch-path "$build_dir" -c release --product tripwire
mkdir -p dist/linux/desktop dist/linux/resources
cp LICENSE dist/linux/LICENSE
cp "$build_dir/release/tripwire" dist/linux/tripwire
cp desktop/tripwire_desktop.py desktop/requirements.txt dist/linux/desktop/
cp Sources/TripWireApp/Resources/OverlayFrame*.png assets/branding/AppIcon.png dist/linux/resources/
cat > dist/linux/start-desktop.sh <<'LAUNCH'
#!/bin/sh
set -eu
cd "$(dirname "$0")"
exec "${TRIPWIRE_PYTHON:-python3}" desktop/tripwire_desktop.py --cli ./tripwire "$@"
LAUNCH
chmod +x dist/linux/start-desktop.sh
printf '%s\n' 'Built dist/linux. Requires the Swift runtime, SQLite, OpenSSL and Python/Qt; see docs/PLATFORM_SUPPORT.md.'
