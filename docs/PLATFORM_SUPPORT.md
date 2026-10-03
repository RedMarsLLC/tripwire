# Platform support

TripWire is being ported to macOS, Linux and Windows. These are **different maturity levels**, not a claim of feature parity or exhaustive host monitoring.

| Area | macOS 14+ | Linux | Windows |
| --- | --- | --- | --- |
| Evidence store, baseline, findings, CLI | Existing implementation | Builds and tests on Ubuntu 24.04 ARM64 | Port implemented; native validation pending |
| Desktop | Native SwiftUI/AppKit | Python/Qt desktop and transparent overlay | Same Python/Qt desktop; native validation pending |
| Process snapshots | Native APIs | Bounded `/proc` metadata | Tool Help, image path, creation time, account SID |
| TCP/UDP inventory | Existing adapter | IPv4/IPv6 current network namespace; owner unknown | IP Helper IPv4/IPv6 owner-PID tables; process instance unverified |
| AI-associated open files | Same-user libproc snapshots | Same-UID `/proc/PID/fd` snapshots and revalidated ancestry | Unavailable |
| Kernel inventory | Installed kernel bundles and registered system extensions | Loaded dynamic modules from `/proc/modules` | Unavailable |
| Apps, startup, hardware, configuration | Existing scoped adapters | Unavailable | Unavailable |
| Host CPU and RAM | Existing definitions | `/proc/stat`, MemTotal minus MemAvailable | GetSystemTimes, physical total minus available |
| AI-app CPU, memory pressure, swap, GPU | See macOS metrics documentation | No AI-app CPU, pressure grading, swap or GPU adapter | No AI-app CPU, pressure grading, swap or GPU adapter |
| Exact file/process event audit | Unavailable | Unavailable | Unavailable |

Linux currently targets little-endian x86-64/ARM64 with procfs; Ubuntu 24.04 ARM64 is the locally tested target. Windows targets Windows 10/11 x64 initially. Other distributions, Windows ARM64, Wayland compositors and multi-monitor configurations need native validation. Missing adapters are shown in Checks before collection starts. Administrator/root access cannot supply an unimplemented adapter.

## Architecture

Swift retains ownership of collection, evidence, detection and correlation. `CTripWirePlatform` provides small Windows API boundaries and system SHA-256 on Windows/Linux. The existing macOS application remains native. Windows/Linux use `desktop/tripwire_desktop.py` with Qt Widgets: no web server, listening port, browser engine or remote content.

The portable desktop starts bounded, read-only CLI queries. **Start monitoring** creates an owned foreground CLI child; Stop/Quit requests its graceful shutdown over a private pipe. Another owner's lock is respected. Opening a viewer does not create an evidence database or start security collection. Once shown, the overlay's separate CPU/RAM process continues while the overlay is hidden. Quitting the application, sleep or actual sampler failure produces an unknown interval, not invented points.

Three artwork layouts are available: Super compact, Horizontal and Vertical. The square expands; Shrink appears only when expanded. Drag the logo/header. Dashboard and metric links reuse one dashboard. CPU click/drag investigations query the selected interval directly from the store, bounded to 200 events/findings each; truncation is explicit. Finding explanations resolve evidence IDs independently of the recent-events list. The portable UI has fewer instruments and filters than the macOS UI.

Wayland controls placement and may restrict always-on-top/edge positioning. TripWire requests native system dragging; it does not work around compositor security. Offscreen/Xvfb tests cannot verify dragging, focus or tray behavior in a real desktop session.

## Linux development

Install Swift 6.2.3 using [Swift's Linux instructions](https://www.swift.org/install/linux/). Ubuntu 24.04 dependencies:

```sh
sudo apt-get install libsqlite3-dev libssl-dev python3-venv \
  libglib2.0-0t64 libgl1 libegl1 libxkbcommon0 libdbus-1-3 \
  libxcb-cursor0 libxcb-icccm4 libxcb-keysyms1 libxcb-shape0 \
  libxcb-xinerama0 libxcb-randr0 libxcb-render-util0 libxcb-xfixes0 \
  libxcb-xkb1 libxkbcommon-x11-0
swift test
sh scripts/build-linux.sh
python3 -m venv .venv
.venv/bin/pip install -r desktop/requirements.txt
.venv/bin/python desktop/tripwire_desktop.py --cli dist/linux/tripwire
```

The command installs ordinary build/UI dependencies, not TripWire monitoring providers. Run TripWire without sudo. The packaged developer directory can also be launched with `TRIPWIRE_PYTHON=/absolute/path/.venv/bin/python dist/linux/start-desktop.sh`.

Default store: `$XDG_STATE_HOME/tripwire/events.sqlite` when that setting is absolute, otherwise `~/.local/state/tripwire/events.sqlite`. New evidence directories/files are private to the current user. Symlink, hard-link, ownership and permission checks fail closed; existing permissions are not repaired.

`/proc` may describe the host outside container quotas. Process visibility follows PID namespaces and permissions; sockets follow the network namespace. Kernel modules may describe a shared host kernel. CPU counts steal time as non-idle and iowait as idle. File snapshots observe regular-file descriptors, not actual reads/writes or completed AI actions. Recognition by executable basename is spoofable; disconnected/unrecognized agents and short-lived access are missed. No target file contents, process arguments or environment values are collected.

For isolated builds, `scripts/Dockerfile.linux` provides Swift, SQLite, OpenSSL, Qt and Windows C cross-check tools. Mount source read-only and put build output in a separate ignored directory. Do not mount the host `/proc`, home directory, Docker socket or private store into a test container.

## Windows development (experimental)

Install Swift 6.2.3 and the required Visual Studio C++/Windows SDK components using [Swift's Windows instructions](https://www.swift.org/install/windows/). Also install PowerShell 7, Python 3.12 and vcpkg. In PowerShell, from this checkout:

```powershell
vcpkg install sqlite3:x64-windows
$env:TRIPWIRE_SQLITE_ROOT = Join-Path $env:VCPKG_ROOT 'installed/x64-windows'
./scripts/build-windows.ps1 -Test
python -m venv .venv
.venv/Scripts/python -m pip install -r desktop/requirements.txt
.venv/Scripts/python desktop/tripwire_desktop.py --cli dist/windows/tripwire.exe
```

Set `TRIPWIRE_SQLITE_ROOT` to the actual vcpkg installed directory if your installation uses a different location. The script supplies SQLite header/library search paths and copies its DLL into the developer bundle. Swift runtime DLLs must remain available through the installed toolchain. This is not yet a standalone signed installer.

The default store is `TripWire/events.sqlite` beneath Foundation's current-user application-support directory (with a Local AppData fallback). New directories/files receive an owner-and-SYSTEM-only DACL. Existing files must have the current owner and a private DACL; reparse points, hard links, network/device paths and alternate streams are rejected. Use a new dedicated directory for `--db` so TripWire can create its private DACL. It never modifies an existing directory's permissions. These checks require native NTFS validation before release.

Protected processes remain incomplete. Owner PID on a socket is not a verified process instance or AI attribution. CPU on systems with multiple processor groups remains unavailable rather than reporting one group as the entire host. No ETW session, service, minifilter or kernel driver is installed.

## Verification and release gates

`.github/workflows/platforms.yml` defines native macOS, Ubuntu and Windows jobs. The Windows job is required to test the actual Swift/Windows SDK build, SQLite/DACL behavior, console and desktop process lifecycle. It has not run locally on this Mac; compiling the C adapters with MinGW is only a preliminary check. CI is not a completed check until run on a GitHub repository.

Local verification on 2026-10-03: 150 macOS Swift tests; 10 Linux Swift tests; four portable desktop integration tests both offscreen and on Xvfb/X11; release CLI PTY checks on both macOS and Linux; macOS app packaging; Linux developer bundle packaging; all four Windows C files cross-compiled against MinGW Windows headers. The canonical macOS app was rebuilt. A live restart exposed a blocked Security.framework signing lookup; process signing enrichment now has a two-second total wait budget and at most two outstanding workers, returning unknown on timeout. After relaunch, the macOS overlay again showed all 10 available checks reporting and active file snapshots. No native Windows execution has been performed.

Local commands:

```sh
swift test
python3 scripts/terminal-smoke.py /absolute/path/tripwire
QT_QPA_PLATFORM=offscreen TRIPWIRE_TEST_CLI=/absolute/path/tripwire \
  .venv/bin/python Tests/DesktopTests/test_desktop.py
```

Portable tests cover evidence hashes, read-only first-run behavior, exclusive collector ownership, unsafe store links, legacy identity decoding, partial inventories and Linux parser boundaries. Desktop integration tests use real CLI children with temporary evidence stores, exercising hidden sampling, reusable dashboard, layouts, owned monitoring shutdown and interval investigation. Raw data stays local; CI uploads no inventory/evidence artifacts.

Before advertising general support:

1. Pass the native Windows job and test on a regular non-administrator Windows desktop.
2. Validate X11/Wayland dragging, DPI, screen edges, minimize, tray and multi-monitor behavior; validate Windows console restoration and protected-process failures.
3. Add platform-specific application/startup inventories, Windows driver inventory, Windows AI file observation and per-app resource attribution. Each adapter needs bounded metadata collection and explicit permission/coverage tests.
4. Design separately approved event providers for deeper auditing; no monitoring grants or privileged installation are implicit in this port.
5. Produce relocatable runtime bundles/installers and a release matrix, then signing/notarization and supported-OS testing.
6. Choose the repository license, confirm artwork redistribution terms, add Qt/SQLite/OpenSSL/Swift notices as applicable, and select the GitHub destination before publishing. PySide6-Essentials is pinned in `desktop/requirements.txt`; no project license has been selected automatically.
