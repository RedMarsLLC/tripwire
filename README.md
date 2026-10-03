# TripWire

A host-observation instrument with a native macOS app and an in-progress Linux/Windows port. **Observe → Baseline → Detect Change → Correlate → Explain → Preserve Evidence.**

This is a working, deliberately incomplete Phase 1 foundation. It records observations, changes and visibility gaps. It does not establish that a computer is safe, and it does not assign malicious intent. Entitlement-dependent and unimplemented sensors are explicitly unavailable.

## Platform status

**macOS remains the established implementation. Linux and experimental Windows ports now pass native CI builds, engine tests and portable Qt desktop integration tests.** The ports do not yet have feature parity, standalone installers or completed interactive desktop validation. See [platform coverage, build instructions and release gates](docs/PLATFORM_SUPPORT.md).

## Build and run (macOS)

Runs on macOS 14+. Build with Xcode 16 / Command Line Tools providing the macOS 15 SDK and Swift 6 or newer. No third-party package dependencies, server, account or API key.

```sh
cd ~/repos/tripwire
swift test
swift build
swift run tripwire doctor
swift run tripwire sample             # one read-only inventory, then stops
swift run tripwire monitor 15         # explicit foreground monitoring; Ctrl-C stops
# In another terminal:
swift run tripwire tui                # shared-store console; does not start collectors
```

The GUI executable is named **TripWireApp**, deliberately distinct from `tripwire` on case-insensitive macOS filesystems. Both products build from this package.

```sh
sh scripts/build-app.sh
open dist/TripWire.app
open dist/TripWire.app --args --show-overlay  # also show the floating overlay at launch
./dist/tripwire doctor
```

The app opens with a read-only store connection. A first-run viewer creates no on-disk database. Use **Snapshot** or **Start monitoring** to collect, and **Stop monitoring** to stop. The **Overlay** button opens the compact floating window. No daemon, login item, privileged helper, system extension or network filter is installed. The local app bundle is ad-hoc signed, not Developer ID signed or notarized.

The overlay uses the supplied transparent TripWire artwork as its only visible frame, with cyan/magenta evidence summaries inside the opening. It defaults to **Compact** (480×270 points), showing finding/reporting counts, resource instruments, the latest finding, coverage and Dashboard. Use the artwork's square button to expand to the detailed (1000-point) view. A labeled **Shrink** button appears at the top-right of the data area only while expanded and returns the overlay to compact size. Your size choice is remembered across app launches. It opens centered and scales to fit the usable screen, leaving room for the menu bar and Dock. Drag the illustrated header (the pointer becomes a hand) to move it, including while another app is active. The artwork's minus and X controls minimize and close the overlay; resizing stays within the current screen. Click a metric, sensor, latest finding or observation to inspect it in the existing dashboard. The overlay hides during inspection; the dashboard's Overlay button brings the same panel back. Counts come from the shared store; unsampled/unreadable values stay unknown, and source details/limitations appear in sensor and evidence tooltips. The native window has no title bar, background or shadow. Reduce Transparency makes the interior data surface opaque while preserving the artwork's outer transparency.

Use **Layout → Vertical** for a tall overlay with the supplied vertical frame and stacked instruments. Compact vertical size is up to 260×780 points; expanded is up to 340×1020, always scaled to fit the usable display. The first vertical presentation starts at the top-right edge. **Layout → Move to left/right/top edge** aligns the visible frame with that edge in either orientation, or drag the logo to any position. There is no extra screen margin: transparent artwork padding is ignored for positioning, and decorative glow/sparks can extend past the edge. The menu bar and Dock still define the usable desktop. **Layout → Horizontal** switches back. Orientation and size persist across launches; each orientation's dragged position is retained while the app is open. The square still only expands; **Shrink** appears above Dashboard only in the expanded vertical layout. Layout/window controls and Dashboard stay accessible if the data area needs scrolling.

Use **Layout → Super compact** for the supplied small widget frame at **300×276 points**. It keeps findings, live-check status, host CPU, a RAM estimate, local AI CPU, and Files/Dashboard links in a small glass panel. The two tiny CPU traces retain point/range investigation; memory and AI CPU values open their details. The square expands this layout to 440 points wide; **Shrink** returns it to 300. Selecting Super compact always starts small. Drag the logo to move it; edge placement, source warnings and continuous hidden sampling work as in the other layouts.

The overlay shows 60-second host CPU and measured swap I/O traces, with a cache-excluding RAM estimate and separately reported OS memory pressure. Its third panel defaults to **AI APPS / LOCAL CPU** (**AI / LOCAL CPU** in vertical mode), showing measured CPU and memory for recognized AI desktop apps, bundled helpers and observed children. These local resources update without hook reports; cloud inference, token usage and individual prompts are not measured. Click for the sampled app breakdown and use the selector for separate **AI / ACTION REPORTS** and per-session evidence links. Action reports require explicitly configured and trusted metadata-only adapters; missing reports remain unknown and resource usage never becomes a fake action count. See [connection details](docs/AGENT_INTEGRATIONS.md) and [resource definitions](docs/OVERLAY_METRICS.md). Click a graph point or drag across a time range to open **Spike Investigation** in the existing dashboard. Selection freezes the chart; the investigation shows the selected measurements, historical AI-app resource samples, gap reasons and links to evidence recorded in that time window. Headline clicks still open resource or source details. Samples update around once per second while small plot canvases scroll at up to 30 fps. After the overlay is first opened, resource sampling continues while TripWire is running—even when the overlay is hidden, minimized or closed. Only the hidden panel’s animation pauses. Reopening shows the continuously collected last minute; sleep, real sampling failures and app exit still interrupt coverage. Opening the overlay does not start security monitoring. **Source connections** distinguishes hook entries found, received reports and freshness; configuration never counts as live coverage.

Dashboard metrics open their underlying records: **Recorded findings** opens searchable explanations, **Observed changes** filters the latest 200 events, **Unknown observations** filters inventory records with unknown baseline/metadata, and **Coverage gaps** opens the interruption history. Findings immediately state what was found and why it was flagged. **Inspect finding** shows before/after metadata, baseline differences, observation confidence, source limitations and suggested checks. Its timeline links to the original evidence, which links back to the finding. Evidence is loaded by ID even when older than the recent-events list; missing records and read failures remain explicit. Findings have no acknowledgement/resolution workflow yet, so their count is labeled recorded findings rather than unresolved incidents.

The monitoring banner distinguishes repeated monitoring, a single snapshot, stopped collection, unreadable evidence, and recent reports from another session. **What is running?** opens sensor groups for reporting, stopped/needs-attention, and unavailable features. Each sensor explains its scope and next step. Unimplemented adapters are identified before the first sample; starting monitoring cannot enable them. Limited visibility means a source is reporting within its declared scope. The optional canary is separately identified as unconfigured until you explicitly create a marker. No permission grants or missing sensor implementations are supplied by the Start button.

**File Activity** shows regular files held open by recognized same-user AI desktop apps and observed descendants. While monitoring, an independent loop targets 2-second checks even when the overlay is hidden. The overlay's **Files** button opens this page even when another check needs attention. A healthy file source also supplies the **FILE WATCH: SNAPSHOTS** status link; failures/staleness take priority in that status line. Rows show path, associated app, holding executable/PID, open capability, last-seen time and supporting evidence. Search by path/app or turn off **Latest check only** to inspect retained history. Credential, startup and extension locations generate review findings even on the first observation; unchanged samples do not repeat findings. Event-only descriptors are explicitly distinguished. No target file contents are read.

Open-file snapshots miss brief opens, closed/mapped files, detached or unrecognized agents, other users and protected processes. A held descriptor can be inherited; its mode does not prove actual reading or writing, an AI instruction or malicious intent. Exact file events require an implemented and approved Endpoint Security deployment; that remains unavailable. See [file-watch source details](docs/COLLECTORS.md#ai-open-file-snapshots).

Default evidence location: `~/Library/Application Support/TripWire/events.sqlite`. All interfaces accept `--db /absolute/path/events.sqlite` (pass app arguments with `open ... --args --db ...`). Keep database, WAL and SHM files together when making a live backup; stop the collector and use SQLite's backup API for a coherent export. Evidence contains sensitive metadata and stays local.

## Terminal and commands

`tripwire` with a terminal opens the interactive console. The original block-letter TRIPWIRE artwork and straight burning fuse appear in the overview at 80 columns by 24 rows or larger, with a condensed summary in shorter windows. Smaller terminals use a text heading. Piped output defaults to plain status. `TERM=dumb` or redirected output disables terminal control sequences. `--ascii` explicitly selects basic-character artwork and borders; `tui --once` prints one frame. The fuse is branding, not a health indicator, and is not animated.

Keys: `f` findings, `e` events, `n` network, `p` processes, `b` baseline, `c` coverage, `d` doctor, `x` explanation, `o` overview, `j/k` scroll/select, `q` quit. Select a finding with `j/k`, then `x` for all explanation sections. Ctrl-C also exits the console and restores terminal settings.

```sh
tripwire status
tripwire sensors
tripwire events --json
tripwire findings
tripwire explain FINDING-ID
tripwire network
tripwire listeners
tripwire processes
tripwire applications
tripwire files                         # observed open-file paths, process/app association, limits
tripwire persistence
tripwire extensions
tripwire hardware
tripwire baseline
tripwire coverage
tripwire doctor
tripwire baseline approve 'EXACT-INVENTORY-ID' --fingerprint SHA256 --confirm
tripwire canary create local-marker
```

Copy the fingerprint printed by `baseline` along with the inventory ID. A changed fingerprint is rejected, and baseline reset is not implemented. Baseline approval changes only TripWire's local metadata for the exact observed fingerprint and records an audit event. It preserves the original baseline. The optional canary command creates only a harmless marker under the store directory. Sample once to baseline it. Only modification/removal is observable; reads and process attribution are not.

## Current macOS scope

- Shared SQLite WAL store, normalized evidence, per-sensor health, independent collector results, source failures, staleness and stored coverage intervals.
- Snapshot inventories for application bundles in `/Applications` and `~/Applications`; processes; TCP connections/listeners and UDP bindings; relevant persistence files; system extension registrations and third-party kernel bundle metadata; USB/whole-storage hardware; selected security posture, DNS, proxy and launchd override metadata.
- On-disk Watchdog executable hashes and store ownership/mode inventory.
- Stable original baselines, before/after evidence, exact-fingerprint user approval, conservative multi-source correlation and complete finding explanations.
- SwiftUI screens and floating overlay; first-class terminal and plain/JSON CLI.
- Deterministic synthetic tests isolated to the test target. Live executables never load fixtures.

The **Security Watch** dashboard page brings app, port, extension and startup-change coverage together, with links to inventories, sensor status and evidence-backed findings. Initial inventories do not approve existing apps. New findings explicitly distinguish an observed change from the unknown agent responsible for it.

**Not yet implemented:** a complete file-access event audit or reliable attribution of host changes to an AI agent; live ES/Network Extension providers, packet/header anomaly analysis, comprehensive privacy/device-use attribution, registered login/background-item inventory, complete kernel-loaded state, all profiles/VPN/Bluetooth/browser persistence, FSEvents, statistical anomaly detection and response actions. The dashboard explicitly exposes unavailable sensors. Snapshot collection is not exhaustive or continuous event capture.

See the [full requirements/status matrix](docs/FEATURE_STATUS.md). Read [architecture and phases](docs/ARCHITECTURE.md), [API/permission matrix](docs/COLLECTORS.md), [data model](docs/DATA_MODEL.md), [security and visibility limits](docs/SECURITY.md), and [verification record](docs/VERIFICATION.md).

Agent activity: [provider support, generic contract and activation boundaries](docs/AGENT_INTEGRATIONS.md). Run `dist/tripwire agents`. On macOS, the canonical runnable app is `dist/TripWire.app`; validation directories contain logs, not distribution copies.
