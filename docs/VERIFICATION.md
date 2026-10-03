# Verification record — 2026-10-01

## Environment and artifacts

Built locally on Apple silicon macOS 26.5.1 using Swift 6.2.3 / Xcode SDK 26.2, targeting macOS 14+. No third-party dependencies were downloaded. Authoritative source: `/Users/jakebrown/repos/tripwire`.

Deliverables:

- `dist/TripWire.app` — native SwiftUI app, locally ad-hoc signed.
- `dist/tripwire` — CLI/interactive terminal.
- `Sources/TripWireCore`, `TripWireCollectors`, `TripWireTerminal`, `TripWireCLI`, `TripWireApp`.
- `Tests/TripWireTests` — 44 unit tests, fixture resources exclusive to that target.
- `scripts/terminal-smoke.py`, `scripts/build-app.sh`.
- README, architecture/phase plan, API/permission matrix, data-model and security/privacy documentation.

## Automated checks

`swift test --scratch-path /tmp/tripwire-build-fixed`: **44 tests passed, zero failures.** Covers normalization, malformed/unsupported source data, original baseline preservation, partial-snapshot safety, absence reliability, explicit approval, new-state aging, before/after explanations, return-to-baseline wording, correlation/PID reuse, database round trips and symlink rejection, stale health, closed/unclean coverage sessions, single collector ownership, no-follow bounded file reads, opaque-file metadata, self-integrity findings, terminal escaping and small layouts. ES tracker tests verify exact field availability boundaries at message versions 0, 1, 2, 3 and 4.

Release packaging builds both executables. `codesign --verify --strict dist/TripWire.app` and `plutil -lint` pass. Ad-hoc signing is only for local development, not a notarized distribution.

`python3 scripts/terminal-smoke.py dist/tripwire`: **four integration groups pass**:

1. Plain/piped ASCII, no ANSI escape output, JSON status and truthful empty-store state.
2. Full canonical wordmark/burning fuse, all navigation keys, resize from 100 to 40 columns, `q` exit and exact termios/cursor/alternate-screen restoration.
3. The same checks with Ctrl-C exit/restoration.
4. The same checks with Ctrl-D exit/restoration.

The PTY test uses an empty temporary database and never starts host collectors. SIGTERM/SIGHUP handlers are implemented but not exercised by this test. No animation is enabled.

## Bounded real-host collection

Explicit one-shot samples ran at ordinary user privilege with no new security/privacy grants. The pre-review release validation snapshot stored **998 evidence records**, **0 findings on initial inventory**, and **8 baselined source scopes**, with **15 reported sensors**. Counts are an observation of this run, not a product default or a safety verdict.

That run included 770 process snapshots, 183 socket records, 24 persistence-file records, 8 USB/storage records, 2 kernel-bundle records, 9 configuration records and 2 Watchdog-integrity records. The system-extension registration inventory was successfully empty at that time. These numbers are time-dependent and intentionally not embedded in either UI.

SQLite quick_check returned `ok`. The persistence source had readable inventory metadata for all scoped items; two content hashes were explicitly unavailable (including an executable helper without user read permission). No grant was requested and no unreadable contents were forced open. Network visibility remained LIMITED. ES, Network Extension, camera, microphone, global privacy and registered background-item capabilities remained visibly unavailable. Each one-shot collector owner reported STOPPED afterward; no continuous monitor was left running.

Earlier development checks caught and fixed (a) macOS case-insensitive output collision between CLI and GUI, (b) unexpected ICMP rows when using broad `lsof -i`, (c) loss of useful metadata when a content hash was unreadable, and (d) terminal layout/restoration edge cases. Source failures were not treated as empty-safe results.

Raw validation databases/logs remain only in ignored local `validation/`. They contain sensitive metadata and are not included in the app or Git history. Counts above are the only host inventory information in this report.

## Remaining validation limits and cleanup

The computer-use tool reported the Mac locked. Native dashboard/overlay visual and interaction QA therefore remains **not performed**; no unlock or permission bypass was attempted. Compiler/linker/signature checks do not substitute for visual QA.

The earlier executable-name collision launched a development GUI process instead of the CLI (PID 58059 at time of diagnosis). A request to stop that specific test process was rejected by automatic approval review under the task's no-process-termination constraint. It was left untouched pending explicit approval; it is a store viewer, not an active collector. Do not assume a PID still identifies it later—verify identity before any approved cleanup.

No persistent daemon/helper, login item, system extension, network filter, external scan, vulnerable service or response action was installed/run. Live ES/NE collection and hardware/privacy adapters listed as unavailable remain deferred, not validated. Statistical anomaly rules and broader persistence sources are also deferred; this is a tested foundation with disclosed incomplete coverage.

## Follow-up requirements/security review

The current deliverables passed **44 unit tests**, all four PTY integration groups, release build/package checks and another bounded real-host sample. Review logs are `validation/review-tests.log`, `review-terminal.log`, `review-package.log` and `review-doctor.json`. The [feature-status matrix](FEATURE_STATUS.md) covers every requested subsystem and records viewer inspection evidence.

Additional regression coverage proves read-only first-run views create no on-disk state and later discover a writer; WAL readers retain a coherent snapshot during a writer commit; read-only connections cannot mutate evidence or acquire a collector lock; private DB/WAL/SHM modes are enforced without chmod; foreign files remain unchanged; failed-complete snapshots and narrowed scopes cannot invent removals; stale approvals are rejected; audit-write failure rolls back approval; missing/future heartbeats are not Active; symlink/shared canary directories are rejected; extension count/identity inconsistencies fail closed.

The actual release CLI's read-only status preserved database bytes and mode. Unsupported baseline reset was rejected before creating state. The bounded review sample passed SQLite integrity, cleared its collector-session marker, and left every one-shot collector stopped/unavailable. The earlier viewer's original store sample timestamp stayed unchanged. No viewer was closed or newly launched during review. Native visual QA and the pending approved-cleanup boundary remain unchanged.

## CLI artwork follow-up

The original block-letter TRIPWIRE wordmark and straight burning fuse now appear in the overview at 80×24, with coverage, sample time, sensor/finding counts, visibility limitations and navigation visible together. A missing `LANG` value no longer silently selects the basic-character fallback; `--ascii` still explicitly selects it.

**49 tests pass**, including empty and populated 80×24 views and layout bounds across the artwork's size thresholds in both character modes. The release package was rebuilt, and all four PTY integration groups pass. The PTY checks now exercise default startup without locale variables, explicit Unicode/ASCII modes, navigation, resizing through 80×24 → 100×55 → 40×20 → 80×24, and q/Ctrl-C/Ctrl-D terminal restoration. These checks use an empty temporary store and start no collectors. Raw output remains in ignored `validation/cli-artwork-tests.log`, `cli-artwork-build.log` and `cli-artwork-pty.log`.

## Dashboard investigation and sensor-status follow-up

**56 tests pass**, including seven investigation tests covering metric routes, first-run implementation gaps, limited/stale/failed/unconfigured sensor distinctions, read-failure recovery without false zero counts, exact finding/evidence links beyond the recent-event window, missing evidence, readable metadata and filter/count consistency. Existing native overlay drag/placement tests still pass. Release packaging, strict ad-hoc signature verification, Info.plist validation and all four CLI PTY groups pass. Logs remain local under ignored `validation/dashboard-tests.log`, `dashboard-build.log` and `dashboard-pty.log`.

Native UI interaction and visual checks were performed on the packaged app. Dashboard metrics opened their intended filtered records; findings opened structured explanations, before/after evidence and clickable timeline records; evidence linked back to its finding. Overlay finding/socket/reporting metrics, an individual unavailable sensor, and the latest-finding entry focused the existing dashboard and hid the overlay during inspection. The supplied overlay frame and its controls remained intact. Large lists use lazy rendering so visible records remain responsive and accessible. The optional canary was verified separately from unimplemented adapters.

The app's existing monitoring session was stopped cleanly for updates and resumed in the final build. Rebuilding changed TripWire's executable and produced genuine self-integrity findings used for inspection checks; no synthetic findings were inserted into the live store. Historical evidence and the recorded update/restart gaps were retained. Acknowledgement/resolution states and the unavailable collection adapters remain unimplemented.

## Overlay resource charts — October 2, 2026 checkpoint

**69 tests pass** (58 existing plus 11 resource/attribution/lifecycle tests), release compilation/package succeeds, strict ad-hoc code-sign verification and Info.plist validation pass, and all four CLI PTY integration groups pass. Logs: `validation/overlay-charts/tests.log`, `build.log`, `terminal.log`. A read-only Mach query smoke check ran; no security inventory or new monitoring session was started by this validation.

A separate review bundle is at `validation/overlay-charts/TripWire.app`, with matching CLI at `validation/overlay-charts/tripwire`. The packaging script now accepts an optional output directory; its default remains `dist`. The existing running `dist/TripWire.app` was neither overwritten nor stopped. Source backups for the pre-change overlay files and README are under ignored `validation/overlay-charts/before/`.

The original frame asset is unchanged. CPU/RAM instruments and pressure state are implemented with 60-second bounded in-memory history, missing/gap semantics, and pause/resume tied to overlay visibility. Agent activity stays UNAVAILABLE; the typed aggregation/marker boundary is testable but no authenticated agent producer exists. See [definitions and primary API references](OVERLAY_METRICS.md).

**Live desktop visual QA and the requested screenshot remain pending.** A read-only permission check reported existing screen-capture access, but the foreground application was `com.apple.loginwindow`. No screenshot, unlock, UI automation, new permission grant or new app launch was attempted through the locked desktop. Existing native drag/placement/navigation tests pass but do not establish that the new chart layout has been visually inspected. No Library screenshot ID exists yet. After unlock, launch the separate review bundle with `--show-overlay`, inspect compact/expanded layouts and controls with real samples, capture only its actual overlay, and upload that verified image through Library.

## Final action/lifecycle and RAM correction — October 2, 2026

The process-CPU fallback has been removed from the interface and collection code. Prepared Codex hooks now cover SessionStart, SessionEnd, UserPromptSubmit, PreToolUse, PostToolUse, PermissionRequest, Stop and Interrupt. Only PostToolUse counts as a received action completion; lifecycle states and last-event time are separate. After 30 seconds without a report the current state becomes UNKNOWN. No hook has been activated or trusted, and no synthetic live reports were inserted. Exact approval/disable/privacy details are in [CODEX_INTEGRATION.md](CODEX_INTEGRATION.md).

**78 tests pass**, including metadata minimization, input bounds, deduplication/evidence links, permission requests versus approval, lifecycle staleness, no idle inference from silence, no Pre/Post double-counting, background reader handoff, chart timing and native drag/placement. Release packaging, strict signature validation, Info.plist validation and all four CLI PTY groups pass. Final review app: `validation/activity-final/TripWire.app`; matching CLI is there and copied to `dist/tripwire` for the prepared hook. The original running `dist/TripWire.app` was not overwritten or stopped. No executable outside this repository was modified.

Charts label RAM as **NON-FREE**, retain the exact measured scale, explicitly say it includes cache and is not a capacity alarm, and expose file-backed, compressed-physical and wired RAM in the tooltip. Pressure is separate and remains UNKNOWN absent a delivered supported pressure notification. No unsupported pressure-state sysctl was substituted.

Read-only diagnostic interval, **12:01:30–12:01:40 UTC**: swap allocation stayed **23,132 MiB (22.59 GiB)**. Across two approximately 5.02-second intervals, swap-in was **0.012 and 0 MiB/s**, swap-out **0 and 0 MiB/s**, page-out **0 and 0.019 MiB/s**, compression **0 and 6.155 MiB/s**, and decompression **2.380 and 23.327 MiB/s**. `memory_pressure -Q` reported its system-wide free metric as **35%** throughout. This is a brief interval with essentially no active disk swapping; it does not establish normal pressure at other times or erase the substantial accumulated compression/swap. Raw physical-free bytes and this utility's metric are different measures.

At **12:01:41 UTC**, `top` reported the largest individual MEM allocations as: `com.apple.Virtualization.VirtualMachine` **8,204 MiB**; `Code Helper` **3,181 MiB**; `launchservicesd` **2,494 MiB**; `fileproviderd` **2,222 MiB**; a `Code Helper (Renderer)` **2,052 MiB**. A `Codex (Renderer)` reported **1,036 MiB**. These are the tool's process memory figures, not additive physical-RAM totals; no arguments or document contents were collected, and no process was terminated. Private diagnostic logs remain under ignored `validation/activity-final/`.

Native checks earlier in the session confirmed the desktop was accessible, and actual expanded/compact review overlays were captured; those images contain the subsequently rejected CPU panel and are **not final deliverables**. At **12:11 UTC**, the fresh same-user/same-console check showed `loginwindow` at display layers **2000/2001**, above the desktop, and the final overlay's accessibility title/control lookup was unavailable. The corrected final build is running as a read-only viewer, but final screenshot capture/Library upload remains pending an accessible desktop. No lock bypass, hook activation, privacy grant or new monitoring service occurred.


## October 2 — canonical app, actionable memory and agent adapters

- Canonical app: `dist/TripWire.app`; five verified validation app copies moved to recoverable Trash. Source/tests/logs preserved. Packaging now rejects alternate output paths. No TripWire Dock shortcut or /Applications copy was present. Exact running executable verified under canonical dist.
- 88 unit tests pass, including cross-provider/subagent identity isolation, metadata privacy, generic schema versioning, old receipt decoding, per-agent lifecycle expiry, cache-excluding RAM accounting, swap delta/reset/gap behavior, native overlay lifetime and existing evidence pipeline tests.
- Release packaging, strict code-signature check, plist validation and all four PTY test groups pass.
- Real approved Codex CLI test delivered SessionStart, UserPromptSubmit, PreToolUse, PostToolUse, Stop and SessionEnd. One actual Bash tool completion for `/usr/bin/true`; exit 0. No raw content retained. See CODEX_INTEGRATION.md for cloud/desktop/manual-shell limitations.
- Canonical expanded overlay visually checked from its actual window, with real CPU, cache-excluding RAM estimate, measured swap rates, and received agent count. Pressure showed UNKNOWN because no Dispatch pressure notification had arrived; no fabricated pressure value. Follow-up changed the RAM headline to the cache-excluding used estimate and its graph to measured swap IN/OUT rates, keeping unknown OS pressure secondary. Screenshots are external development QA, not a product feature.
- Claude Code/Cursor/generic adapters have parser/contract tests, not live-provider verification or activation. No claim of universal AI-agent coverage.

Final follow-up: stale agent receipts display NO LIVE COVERAGE, hide the current action trace, and retain last-report time. Cloud conversation/executor activity is explicitly excluded. The final canonical process and window were verified and captured after the 88-test passing build.

During the final actual-window capture, macOS delivered a real warning pressure notification and the overlay displayed OS PRESSURE: ELEVATED. This confirms the supported notification path works; the earlier initial UNKNOWN was not replaced by a guessed value.


## AI report feed → overlay → evidence (October 2, 2026)

The canonical app now opens agent source status and a selected session's timeline directly from its AI instrument. Per-identity traces remain separate from the aggregate and preserve unknown gaps. A bounded read-only probe reports matching default-user hook entries separately from actual delivery; it never activates providers or treats configuration as live coverage.

All 92 tests pass. New checks cover separate provider/identity freshness, per-agent traces, staleness, configuration bounds/exact command matching, and a test-only stored report reaching the actual overlay model and dashboard evidence lookup. Release packaging, strict signature verification and all four terminal smoke groups passed.

A temporary local Codex CLI session used the existing trusted configuration and executed `/usr/bin/true` once. Its actual lifecycle and Bash completion reports reached the shared store, appeared in the overlay, and opened the matching session timeline and original evidence. The temporary CLI session was then exited. No synthetic receipt was inserted into the live store, no other provider was activated, and no trust bypass or configuration edit was used. Claude Code/Cursor delivery and cloud-orchestrated sessions remain outside this live verification. The app's existing security monitoring remained off.

## Local AI app resources and drag regression (October 2, 2026)

The default third instrument now samples local recognized AI desktop app CPU and memory independently of hook reports. Native validation showed changing measured app counters and a timestamped per-app resource snapshot in the existing dashboard. The selector retains the separate action-report feed. Local app association does not identify individual questions or measure remote inference, tokens, GPU work or browser-only AI.

All 100 tests pass, including a real process CPU clock comparison, Mach tick conversion, whole-host normalization, PID reuse, process churn, path boundaries, parent-instance ordering, interrupted/unknown intervals, and visible/hidden app sampling. Release packaging, strict signature verification and all four PTY groups pass. An existing frozen-clock fixture now uses an exact stored timestamp precision to avoid submillisecond round-trip flakiness.

The native header's hit surface is no longer completely transparent. Real mouse drags were verified against read-only geometry for TripWire's own window: compact after live redraws, expanded, and compact again after shrinking and dashboard navigation. Synthetic native event tests additionally cover four widths, first-click hit testing and control exclusion. Raw QA geometry and logs remain under ignored validation/. The canonical app was reloaded and left compact with local resource measurements visible; security monitoring remains off.

## Spike selection and investigation (October 2, 2026)

105 tests pass. New tests cover point/range coordinate mapping in both directions, frozen snapshot isolation, gaps without fabricated nearby values, bounded historical app frames after app exit, and indexed time-window evidence lookup beyond the recent-events list with explicit truncation. Release packaging, strict signing verification and all four PTY groups pass.

Native UI verification exercised an expanded host-CPU range drag, a compact AI-CPU point click, widening, reverse dragging on the frozen inspector chart, and navigation away/back with the refined interval preserved. The existing dashboard was reused. Captured values remained tied to their original times. The live selected interval had no stored evidence; its unknown-coverage explanation was verified. Positive event/finding correlation and original event lookup were verified with test-target fixtures only, without synthetic observations in the live store. Security monitoring remained off.

The inspector shows measured sample peaks, historical recognized AI-app resource usage, both swap directions, chart scale and source limitations. Temporal matches do not establish causality; unmeasured host processes, GPU work and cloud inference remain outside resource attribution. Resource history remains in memory and bounded to the current 60-second capture; a selected capture survives navigation until replaced or cleared.

## Agent security scope and installed applications (October 2, 2026)

- Added a scoped application bundle collector, APP observations, baseline change findings and CLI `applications` inventory. Security Watch links app, network, extension and startup coverage to sensor explanations and findings; finding detail and CLI explanations state that responsible-agent attribution is unknown.
- 113 Swift tests passed. New tests cover allowlisted manifest fields, nested bundle exclusion, fresh same-path version reads, baseline/add/change/removal evidence, unknown actor/intent, malformed manifests, symlinked manifests/roots, entry/depth bounds, and preservation of prior evidence when a folder becomes an excluded link. A non-app documentation link can no longer prevent a baseline for the declared plain-folder scope; removal inference remains disabled.
- Release packaged to the canonical `dist/TripWire.app`; strict/deep signature verification passed. Four PTY smoke groups passed (plain/JSON, default startup and resize, Ctrl-C, ASCII/Ctrl-D). Raw logs remain in ignored `validation/security-watch-*.log`.
- Live application inventory completed its scoped baseline. One excluded non-app symlink kept removal inference unavailable, with an explicit sensor explanation. No synthetic host changes or findings were created. Native UI verified Security Watch navigation, application sensor status, before/after finding evidence and the new attribution explanation.
- Left the canonical app open on Security Watch with foreground monitoring active. No root grant, privacy grant, persistent installation, OS extension, automatic blocking or response action was performed. Exact file access, reliable agent ancestry, kernel load events and comprehensive agent attribution remain unimplemented.

## Clear check status and current memory pressure (October 3, 2026)

- Replaced the unexplained registry fraction and generic degraded/incomplete summary with paused/start, starting, failed-check and missing-report states. Available/live counts exclude the six unimplemented features and an unconfigured optional canary. The checklist explains who defines the checks and exposes names, scope, reasons and next steps. A fully reporting current build still identifies missing AI file-access monitoring directly. The dashboard, overlay and terminal no longer equate a mixed registry total with coverage.
- Added a fixed-size read-only current-pressure sysctl query to the visible overlay's host tick, validated against Apple's XNU source and installed Dispatch/event constants. First samples and fresh samples after gaps report an observed grade immediately. Denied/missing/malformed OS results remain unavailable with specific diagnostics. No pressure generation, purge, sysctl write or automatic memory response is used.
- 121 Swift tests passed, including exact grade/size validation, denied/unsupported reads, first/post-gap readings, stale grade invalidation, registry exclusions, stale/failed source routing, unreadable-store handling and canary failure vs optional configuration. Release build and strict/deep codesign verification passed; all four PTY smoke groups passed. Logs remain in ignored `validation/status-pressure-*.log`.
- Native UI verified both overlay sizes, direct Start from the paused overlay, the live check count opening the full named checklist, and the pressure details popover with timestamp/source/action guidance. macOS supplied an elevated grade during this check. Left the canonical app's foreground monitoring active with nine scoped checks reporting and the compact overlay restored. No entitlement/privacy grant or persistent installation was added.

## TripWire application icon (October 3, 2026)

- Added a cyan/magenta TW and trip-wire icon with transparent exterior, original artwork and generation prompt under `assets/branding`, and a repeatable native icon packaging script. The ICNS round-trip contains all ten standard/Retina representations, including a 1024-pixel image with alpha. Bundle metadata declares the icon; the app also sets it on launch for SwiftPM development runs.
- 121 Swift tests and all four PTY smoke groups pass. Release packaging, strict/deep signature validation, Info.plist validation and matching source/bundled icon hashes pass. Raw logs stay in ignored `validation/app-icon-*.log`.
- Relaunched the canonical app and visually verified the new icon in its native About panel. The Dock could not be inspected directly through the UI tool. Restored foreground monitoring with nine scoped checks reporting and the compact overlay visible. The rebuild's genuine self-integrity finding remains recorded.

## Vertical overlay (October 3, 2026)

- Added the supplied tall frame with transparent exterior/opening and a fitted glass data well. The Layout menu switches horizontal/vertical orientation and offers left/right edge placement. Both layouts use the same live metrics model and investigation routes. Native drag geometry changes with orientation; the square remains expand-only, with Shrink only in expanded mode. Orientation/size preferences persist; per-orientation frames are retained during the app session.
- 124 tests pass, including vertical fitting on short and offset screens, both edge placements, edge-preserving resize, offscreen recovery, orientation preference handling, and native drag/control exclusion across both orientations and four widths. Release packaging, strict/deep signing validation, Info.plist validation and four PTY smoke groups pass. Logs remain in ignored `validation/vertical-overlay-*.log`.
- Native UI verified both layout directions, remembered vertical orientation after restart, left-edge placement, header drag interaction, expand/Shrink, and a vertical CPU graph opening Spike Investigation in the existing dashboard. Narrow labels and the glass well were adjusted after visual inspection. The final canonical app is running with foreground monitoring restored and the compact vertical overlay at the right edge. Rebuild self-integrity findings and restart gaps remain real stored evidence; no fixtures were inserted.

## Overlay edge placement (October 3, 2026)

- Removed the forced 24-point screen inset. Placement and size fitting now use each artwork's visible frame outline, allowing the transparent canvas and projecting decorative sparks/glow beyond the usable desktop boundary. The raw native window rectangle no longer creates a hidden keepaway. Resize preserves the visible outline's position, and display changes still recover an offscreen frame. The Layout menu exposes left, right and top placement for both orientations; the menu bar and Dock retain their normal usable-desktop boundary.
- 126 tests pass. Placement checks cover exact top corners for both orientations/sizes, repeated fitting without bounce, side-preserving resize, narrow/offset screens and native drag/control dispatch. Native-window checks confirm that AppKit accepts the calculated frame with its transparent top margin outside the usable desktop, allowing its normal whole-point rounding. Release/signature/Info.plist validation and all four PTY smoke groups pass. Logs remain in ignored `validation/overlay-edge-*.log`.
- Relaunched the canonical app, restored its monitoring workflow, exercised the top/right menu actions and header drag, and left the compact vertical overlay aligned at the top-right. No artwork pixels, collection scopes or privacy permissions were changed.

## AI open-file snapshots (2026-10-03)

Implemented the metadata-only libproc collector, independent foreground file loop, File Activity dashboard, permanent overlay Files button, CLI `files`, and sensitive-location findings. Source scope and missing event-level coverage remain explicit. No privileged deployment or permission grant was added.

- `swift test` with the existing isolated scratch/cache setup: **138 tests passed, zero failures** (`validation/file-watch-tests.log`). New cases cover actual native descriptor modes including event-only, process and ancestry identity races, access denial, output bounds, sensitive-path boundaries, initial/partial finding creation, duplicate suppression, retained evidence lookup, no removal inference, stale UI status, and cancellation during a blocked sibling collector.
- `sh scripts/build-app.sh` rebuilt the sole canonical `dist/TripWire.app` and `dist/tripwire`; strict/deep code-signature verification passed. Four terminal-smoke groups passed (`validation/file-watch-pty.log`).
- Native UI validation confirmed real file observations with process/app association and mode, row-to-evidence navigation, and the overlay Files button opening File Activity in the existing dashboard. Compact vertical layout keeps Files and Dashboard visible. Monitoring and the compact overlay were restored.
- Release CLI JSON was checked for actual file observations, process identity, open mode and source limitations. Raw metadata remains local in ignored `validation/file-watch-live-files.json`.
- An existing process/signing inventory was slow during live validation. File snapshots continued independently; the unrelated sensor warning remained visible. This change does not solve synchronous system API stalls. A normal app quit during that pending round leaves session interruption evidence for the next launch; it is not claimed as a clean completed check.

This verifies open-file snapshot coverage only. Short-lived accesses, actual reads/writes, detached/unrecognized agents, protected processes, complete ancestry and Endpoint Security event delivery remain unverified/unavailable. No claim of exhaustive file access monitoring or zero event loss is made.

## Overlay graph continuity (2026-10-03)

Resource collection now continues after the overlay is first opened, independent of hiding, minimizing, closing or opening dashboard investigations. Visibility controls chart animation only. The bounded 60-second histories and counter baselines remain active. A process activity keeps this user-requested sampling out of App Nap while permitting normal idle system sleep; sleep still invalidates intervals, and wake resumes an enabled sampler even with its panel hidden. App termination stops the sampler and releases the activity.

- **139 tests passed, zero failures** (`validation/overlay-continuity-tests.log`). The timer regression hides the panel longer than the three-second continuity limit and verifies advancing host, swap, AI-app and hook histories, plus unchanged counter/history state on reopening. Sleep/wake tests retain genuine gaps and confirm shutdown prevents automatic restart.
- Canonical app/CLI rebuilt with `scripts/build-app.sh`; strict/deep signature verification and Info.plist validation passed. Four PTY smoke groups passed (`validation/overlay-continuity-pty.log`).
- Native close/reopen validation left the actual overlay closed for approximately 50 seconds while TripWire stayed open. Reopening displayed continuously collected CPU, swap and AI-app traces across the hidden interval. The compact vertical overlay and prior monitoring state were restored.

## Super compact overlay (2026-10-03)

Added Layout → Super compact using the supplied transparent widget artwork unchanged. The 300×276-point presentation keeps findings, scoped check status, measured host/local-AI CPU traces, RAM estimate and Files/Dashboard links. The square expands to 440 points wide; the labeled Shrink control appears only while expanded. It shares the existing sampler, history and investigation routes. No new collection source or permission was added.

- **140 tests passed, zero failures** (`validation/super-compact-tests.log`). Placement/preference tests cover the new dimensions and visible-edge alignment; native header drag/control exclusion and screen-fitting cases now exercise all three layouts.
- Canonical app rebuilt, strict/deep signature and Info.plist checks passed, and all four CLI PTY smoke groups passed. Build and PTY logs remain in ignored `validation/super-compact-*.log`.
- Native UI verified the supplied frame without system window chrome, remembered layout after restart, working logo drag, square-to-expand/Shrink, and small-graph investigation. Files and Dashboard both reuse the existing dashboard. A clipped AI CPU label was corrected and the final small layout visually rechecked, including unknown readings during initial measurement. Monitoring was restored and Super compact left selected. Genuine rebuild/self-integrity observations remain in the store.

Resource history remains transient and bounded. This change does not fabricate measurements during sleep, sampler failures, clock discontinuities or app exit, and does not repair the separately observed slow general inventory collector.
