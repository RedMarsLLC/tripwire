# TripWire application icon

`AppIcon.png` is the original transparent artwork, created with the built-in image generation tool. The exact prompt is retained in `AppIcon.prompt.txt`.

Run `sh scripts/build-icon.sh` after changing the artwork. It uses macOS `sips` and `iconutil` to produce `Sources/TripWireApp/Resources/AppIcon.icns` with standard and Retina representations from 16 to 1024 pixels. The generated ICNS is included in the source tree so ordinary Swift builds do not need to regenerate artwork.

`sh scripts/build-app.sh` copies the icon into the canonical app bundle and declares it through `CFBundleIconFile`. The app also sets its icon at launch from the SwiftPM resource so direct development launches have the same Dock identity.

The user's vertical frame was isolated from its broad background with built-in image generation. The transparent project asset is `Sources/TripWireApp/Resources/OverlayFrameVertical.png`; its edit prompt is retained in `OverlayFrameVertical.prompt.txt`. The original horizontal frame is unchanged.
