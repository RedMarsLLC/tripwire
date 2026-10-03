# TripWire engineering invariants

The repository is a Swift package with a native macOS app and experimental Linux/Windows adapters plus a Qt desktop. Build with `swift test`; package macOS with `sh scripts/build-app.sh`, Linux with `sh scripts/build-linux.sh`, and Windows with `scripts/build-windows.ps1`. Run `python3 scripts/terminal-smoke.py dist/tripwire` for macOS PTY checks; use the Linux binary path on Linux. See `docs/PLATFORM_SUPPORT.md` for native validation gates.

- Keep `tripwire` and `TripWireApp` executable names distinct on case-insensitive filesystems.
- Never fabricate live observations. Synthetic fixtures belong only to the test target.
- Unknown/unavailable telemetry must not become nominal, zero-loss, or a safety claim.
- A failed/partial inventory cannot establish absence. Keep original baseline evidence; age is not trust.
- Confidence describes observation quality; malicious intent remains unknown unless separately established by evidence.
- Collection remains read-only apart from the private store and explicit canaries. No global privacy/security grants, persistent installation or system/network changes without explicit authorization.
- Do not collect payloads, user documents/browser contents, recordings, screenshots, keystrokes, process arguments or environment values.
- Retain source limitations in events, findings and every interface. No unsupported coverage percentage.
- Use fixed executable paths/argument arrays, bounded output, no shell interpolation; sanitize terminal text at display boundaries.
- Keep raw validation data local under ignored `validation/`; do not commit, upload or paste it into reports.
- Separate collection, storage, detection, correlation, presentation and any future approved response work.
