# Overlay resource instruments

Implemented October 2, 2026. Updated with [opt-in multi-provider action/lifecycle reports](AGENT_INTEGRATIONS.md). The original artwork, fuse, transparent native panel, drag area, size preference, minimize/expand/shrink/close controls and dashboard routes are preserved. Three instrument panels occupy the existing data well. Expanded mode retains evidence and individual-sensor links in **Inspect**; compact mode retains findings, latest finding, reporting, coverage and dashboard links.

## Scope and provenance

These are transient host resource instruments, not threat scores or security coverage. `TripWireCollectors.HostResourceSampler` reads aggregate Mach counters. `TripWireCore.ResourceMetrics` normalizes, checks continuity, and retains bounded history. `OverlayMetricsModel` owns session-long sampling independently of the panel’s visibility. The existing evidence summaries still read the common SQLite store. Resource ticks are not written to that store, avoiding one-second evidence noise and indefinite resource-history retention. No security inventory starts because the overlay was opened.

| Instrument | Source and definition | Missing visibility |
|---|---|---|
| CPU / HOST | `host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO, ...)`. `100 × Δ(user + system + nice) / Δ(user + system + nice + idle)`, aggregated over all processors. 100% means the whole machine's reported CPU time was busy; there is no extra division by core count. | First sample, zero total delta, failed query, counter decrease/wrap/reset or interrupted interval: UNKNOWN, no plotted value. A measured all-idle interval is a legitimate 0%. |
| OS PRESSURE (clickable secondary status) | Read-only `sysctlbyname("kern.memorystatus_vm_pressure_level", ..., nil, 0)` on each host tick, plus Dispatch notifications between ticks. Exact UInt32 values 1/2/4 map to NORMAL/ELEVATED/CRITICAL. The current value is available on the first sample without waiting for a transition. | This XNU diagnostic is version-dependent, not a stable documented application API. Denied/unavailable/unrecognized reads are explicitly unavailable with a reason and next step. No fallback to invented normal or a RAM percentage. A new successful query can restore pressure immediately after a gap; CPU still needs two samples. |
| Used RAM estimate / total | Public Mach VM bytes: (`internal_page_count` − `purgeable_count` + `wire_count` + `compressor_page_count`) × page size. Excludes file-backed cache and purgeable anonymous memory. Total is `ProcessInfo.physicalMemory`. Physical compressed and wired amounts are in details. | An explicitly labeled estimate, not an exact reproduction of Activity Monitor accounting. Invalid/overflow/inconsistent counters remain UNKNOWN. No severity from occupancy. |
| Swap IN / OUT MiB/s | Separate deltas of public `swapins` and `swapouts` counters × page size / measured uptime interval / 1,048,576. Shows current traffic rather than cumulative allocation. Two 60-second traces (IN cyan, OUT amber) share an explicitly displayed dynamic MiB/s scale; color indicates direction, not severity. | First/reset/missing/gap intervals are UNKNOWN. A valid unchanged counter yields measured zero. Does not by itself establish system responsiveness or pressure. |
| AI APPS / LOCAL CPU (default third panel) | Recognized running desktop apps from NSWorkspace; same-user process inventory, exact bundle-path membership and observed descendants; `proc_pid_rusage` user + system Mach ticks converted with `mach_timebase_info`. CPU = 100 × elapsed process CPU seconds / elapsed uptime / active logical cores. RAM = summed process physical footprints. Selector supports individual apps. | First, reset, reused-PID, missing, stale and interrupted intervals are unknown. Partial process sets are marked ≥ (observed lower bound). Cloud compute, tokens, GPU work and individual prompt attribution are unavailable. |
| AI / ACTION REPORTS (selector option) | Provider-neutral received completion/failure counts and per-identity lifecycle reports. Codex, Claude Code, Cursor parsers and generic v1 contract. Selector separates identities. | No reports means UNKNOWN, not idle. A parser's existence does not mean a provider is connected. Resource usage never becomes an action count. [Adapter coverage and setup](AGENT_INTEGRATIONS.md). |



## Sampling and discontinuities

- Approximately one sample per second, timer tolerance 150 ms. Host ticks perform two fixed-size Mach statistics queries, one page-size query and one fixed-size read-only pressure sysctl. Independent background workers query bounded hook receipts and app resource counters. App sampling checks at most 4,096 same-user PIDs, 32 recognized apps and 32 parent-chain passes; inaccessible or truncated inventories remain partial. No shell commands, arguments, environment values, prompts or transcripts are collected.
- First opening the overlay starts resource sampling for the app session. Dashboard inspection, hiding, minimizing and closing the panel keep the timer, pressure source and histories running. Hidden chart animation pauses. Sleep interrupts sampling; wake resumes an enabled sampler even if its panel is hidden. App exit ends sampling and its process activity; no persistent service is installed. The sampler uses a user-initiated activity that prevents App Nap while allowing normal idle system sleep.
- History spans 60 seconds with a hard maximum of 64 points per instrument. Histories remain in memory only and prune continuously while hidden. Visibility changes insert no missing points and do not reset CPU/swap baselines.
- Intervals longer than 3 seconds, backward clocks/uptime or a wall-clock/uptime delta disagreement of at least 0.5 seconds break CPU continuity and reset pressure. Sleep/wake notifications explicitly invalidate the interval.
- Nil, stale and non-finite readings never become zero. Trace segments do not bridge nil values or intervals over 3 seconds. Wall-clock reversal starts a fresh history. RAM can show a new instantaneous reading after a gap while CPU waits for a second counter sample.
- Charts show real sample positions; the small plot canvases move timestamps at up to 30 fps independently of 1 Hz measurement. There is no extrapolation, invented sample, decorative sweep or fixed “healthy” trace; Reduce Motion uses 1 Hz rendering. A short history occupies only the right side of the 60-second grid.
- Resource metrics do not increment sensor coverage, create findings or establish malicious intent. Action reports and app resources remain separate measurements.

## Permissions and primary references

No Endpoint Security, Network Extension, root, Accessibility, Screen Recording or new privacy grant is required by these resource instruments. The product does not capture screenshots; any explicitly requested development screenshot is a separate QA operation.

Checked against Apple's public macOS 26.2 SDK headers (`mach/host_info.h`, `mach/vm_statistics.h`, `mach/mach_host.h`) and official references:

- [Apple host CPU load type](https://developer.apple.com/documentation/kernel/host_cpu_load_info_t)
- [Apple VM statistics type](https://developer.apple.com/documentation/kernel/vm_statistics64_data_t)
- [Apple Dispatch memory pressure source](https://developer.apple.com/documentation/dispatch/dispatchsource/makememorypressuresource(eventmask:queue:))
- [Apple's published Mach host definitions](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/host.defs)
- [Apple's VM statistics definitions, including speculative/free-page semantics](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/vm_statistics.h)
- [Apple physicalMemory](https://developer.apple.com/documentation/foundation/processinfo/physicalmemory)
- [Apple process activity that allows idle sleep](https://developer.apple.com/documentation/foundation/processinfo/activityoptions/userinitiatedallowingidlesystemsleep)
- [Apple NSWorkspace sleep notification](https://developer.apple.com/documentation/appkit/nsworkspace/willsleepnotification)

## Initial pressure limitation

Verified against the installed macOS 26.2 public `dispatch/source.h` and [Apple libdispatch source](https://github.com/apple-oss-distributions/libdispatch/blob/main/dispatch/source.h): the source monitors changes; NORMAL is a return-to-normal event. This overlay received no initial notification during live validation. `dispatch_source_get_data` is only defined inside the callback, so polling it for an initial grade is invalid. A bounded diagnostic `memory_pressure -Q` produced a free-memory percentage, not a documented normal/warning/critical grade; it is not used as a product pressure source. No private pressure sysctl is used and no artificial pressure was induced. Thus used RAM and real swap I/O are the prominent measured alternative, with unknown pressure retained as a secondary limitation.

## Validation

`swift test` covers normalization, genuine zero vs missing values, counter resets, RAM validation/overflow, missing independent sources, initial pressure, sleep/gaps/staleness, history bounds, attribution requirements/deduplication/coverage, and continuous hidden-window sampling, reopen continuity and hidden sleep/wake lifecycle. A bounded read-only Mach smoke test accepts unavailable source results explicitly. Existing native drag/resize/navigation tests remain in place. This is not a claim of full on-screen visual verification; see the latest verification record for that session's status.

## AI desktop app resource scope

The third panel defaults to measured local CPU and memory, independent of action-hook setup. It recognizes Codex/ChatGPT bundle IDs and exact registered app names for Claude, Cursor, Ollama and LM Studio. This is metadata-based grouping, not authenticated AI detection. Bundled helpers and currently observed descendants contribute; exited or inaccessible processes can be missed. Resource history stays in memory. Remote model execution, browser-only AI and unrecognized applications are outside this view. A question may involve little local CPU even while cloud inference is busy. Memory sums may contain shared accounting.

Click the instrument for a timestamped snapshot in the existing dashboard. The dashboard keeps the snapshot captured at the time of inspection; resource collection continues independently. The selector retains the separate action-report view and per-session evidence links. CPU uses a displayed dynamic 5–100% graph scale and whole-host normalization; it never supplies fake action reports or security findings.

Process counter units were checked against Apple's [task resource accounting](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/task.c) and [rusage population](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/bsd_kern.c). A native test compares converted process counters against CLOCK_PROCESS_CPUTIME_ID rather than assuming ticks are nanoseconds.

The native header retains a 1% alpha hit surface above the SwiftUI view. A fully clear layer can lose mouse delivery at the borderless window boundary; AppKit-only synthetic drag events do not exercise that boundary. Regression tests check the hit surface and native movement across compact/expanded sizes.

## Selecting spikes and time ranges

Click a plot for a four-second neighborhood, or drag a time range in either direction. The plot clock, points and related metric snapshot freeze at mouse-down; a cyan band marks the selection. Release opens Spike Investigation in the existing dashboard. The app retains at most 64 frames / 60 seconds of app resource detail, alongside host CPU, used-RAM estimate, swap and pressure history. A dismissed or restarted app cannot recover older resource measurements.

The inspector supports widening the selection, inspecting the whole minute, and dragging on a larger frozen chart to refine it. It shows observed sample peaks, sample counts, historical AI-app CPU/memory, explicit unknown intervals and gap reasons. CPU/swap are averages over sampling intervals, not instantaneous maxima. App history survives an app's exit within the retained window. Only recognized AI apps have resource attribution; other processes and GPU/remote work are outside its scope.

A read-only indexed query retrieves up to 200 observations and 200 findings by the selected timestamp bounds, independently of the dashboard's recent list. Saturation is labeled LIMITED. Each record links to its original evidence or finding explanation; Back to spike investigation preserves the chosen range. Temporal overlap is context, never proof of cause. Source timestamps reflect observations or hook receipt time; polling and missing hooks can miss or delay activity. Action-chart values are rolling 60-second counts, while evidence is filtered by actual timestamps within the selection. Missing or unreadable evidence never establishes absence.

This remains transient local inspection. Opening the inspector hides the overlay but keeps resource sampling running; the selected investigation remains frozen at its capture time. It does not start monitoring, install integrations, collect payloads, or write resource ticks to the evidence store.

## Actionable check status (October 3, 2026)

The overlay displays a named security-check state/count instead of a fraction over all registry entries. The current registry contains nine standard inventory checks, six unimplemented features and one optional canary check. Unimplemented features and an unconfigured canary are excluded from the available/live count; a configured canary participates. Clicking the count opens the named checklist and explains that TripWire defines the list, not macOS or an AI agent. This is not a coverage percentage. Resource charts and security inventory collection have separate lifetimes.

Stopped collection displays **Checks paused · Start** with a direct foreground Start action. Failed checks link to their reasons, stale/missing reports are separate, and a fully reporting set still explicitly discloses the absent AI file-access collector. The checklist separates implemented checks, future adapters and optional configuration, with per-source next steps. Pressure opens a details popover with source, timestamp, concrete read errors or pressure guidance, plus an Activity Monitor launcher.

The pressure mapping/read-only behavior was checked against Apple's [XNU pressure sysctl and conversion](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_memorystatus_notify.c) and the installed `sys/event.h`/Dispatch constants. No pressure generation, purge command, sysctl write or new privilege is used by TripWire.
