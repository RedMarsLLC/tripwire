import SwiftUI
import AppKit
import TripWireCore

/// Resource values are transient instruments, separate from security findings.
struct RetroMetricsStrip: View {
    var resources: ResourceMetrics
    var appResources: AppResourceMetrics
    var hooks: AgentActivityView
    var hookHistory: AgentActivityHistory
    var live: Bool
    var compact: Bool
    var vertical = false
    var inspect: (String?) -> Void
    var inspectResources: () -> Void
    var inspectRange: (MetricInspection) -> Void
    @State private var selectedIdentity: String?
    @State private var showReports = false
    @State private var selectedApp: String?
    @State private var showPressureDetails = false
    private let phosphor = Color(red: 0.35, green: 1, blue: 0.68)
    private let cyan = Color(red: 0.05, green: 0.91, blue: 1)
    private let amber = Color(red: 1, green: 0.76, blue: 0.3)

    var body: some View {
        let now = Date()
        let fresh = resources.isFresh(at: now)
        let cpu = fresh ? resources.cpu.points.last?.value : nil
        let ram = fresh ? resources.latestRAM : nil
        let layout = vertical ? AnyLayout(VStackLayout(alignment: .leading, spacing: 14)) : AnyLayout(HStackLayout(alignment: .top, spacing: 14))
        layout {
            instrument(title: "CPU / HOST", value: cpu.map { String(format: "%.1f%%", $0) } ?? "UNKNOWN",
                       footer: "60s · CLICK / DRAG TO INSPECT", color: phosphor,
                       points: resources.cpu.points, now: now, limit: 100, missing: cpu == nil ? "NO CURRENT INTERVAL" : nil, focus: .hostCPU)
                .help("Aggregate CPU busy ticks / total tick delta. Whole-host 0–100%, not a per-process sum. First, failed, reset and interrupted intervals are unknown. \(resources.gapReason ?? "")")
            VStack(alignment: .leading, spacing: 3) {
                let pressure = fresh ? resources.pressure : .unknown
                Text("RAM / USED ESTIMATE").font(.system(size: compact ? 15 : 10, weight: .bold, design: .monospaced)).foregroundStyle(cyan)
                Text(ram.flatMap { usage in usage.usedEstimateBytes.map { String(format: "%.1f / %.0f GiB", Double($0) / 1_073_741_824, Double(usage.totalBytes) / 1_073_741_824) } } ?? "RAM UNKNOWN")
                    .font(.system(size: compact ? 20 : 18, weight: .semibold, design: .monospaced)).foregroundStyle(cyan).lineLimit(1)
                let peak = max(0.1, (resources.swapIn.points + resources.swapOut.points).compactMap(\.value).max() ?? 0.1)
                SelectableMetricChart(series: [MetricSeries(points: resources.swapIn.points, color: cyan), MetricSeries(points: resources.swapOut.points, color: amber)],
                                      maximum: peak, live: live, focus: .swap, capture: capture, inspect: inspectRange)
                    .frame(height: compact ? 25 : 20)
                Text(fresh ? resources.swapRate.map { String(format: vertical ? "IN %.2f / OUT %.2f MiB/s" : "SWAP IN %.2f / OUT %.2f MiB/s", $0.inMiB, $0.outMiB) } ?? "SWAP RATE UNKNOWN" : "SWAP RATE UNKNOWN")
                    .font(.system(size: compact ? 12 : 9, design: .monospaced)).foregroundStyle(.white.opacity(0.85)).lineLimit(1).minimumScaleFactor(0.75)
                Button { showPressureDetails = true } label: {
                    Text(!fresh ? "PRESSURE: PAUSED ⓘ" : pressure == .unknown ? "PRESSURE: UNAVAILABLE ⓘ" : "PRESSURE: " + pressure.rawValue + " ⓘ")
                        .font(.system(size: compact ? 11 : 9, weight: .semibold, design: .monospaced))
                        .foregroundStyle(pressure == .critical ? .red : pressure == .warning ? amber : .white.opacity(0.85)).lineLimit(1)
                }.buttonStyle(.plain).help("Click for the current reading, its source and what to do.")
                    .popover(isPresented: $showPressureDetails) { pressureDetails }
                Text(String(format: vertical ? "SWAP · 60s · MAX %.2f MiB/s" : "60s SWAP I/O · SCALE %.2f MiB/s", peak))
                    .font(.system(size: compact ? 10 : 8, design: .monospaced)).foregroundStyle(.white.opacity(0.6)).lineLimit(1)

            }.frame(maxWidth: .infinity, alignment: .leading)
                .help("Memory pressure is read directly from macOS while TripWire's resource sampler is running, including when the overlay is hidden. Click its label for the source, reason and next step. The graph is swap IN (cyan) and OUT (amber), on the displayed MiB/s scale. Used RAM is an estimate excluding file-backed cache. \(ram?.breakdown ?? "Breakdown unavailable"). High RAM occupancy alone is not memory pressure.")
            activityInstrument(now: now)
        }
    }

    private var pressureDetails: some View {
        let fresh = resources.isFresh(at: Date())
        return VStack(alignment: .leading, spacing: 12) {
            Text("Memory pressure: \(fresh ? resources.pressure.rawValue : "sampling paused")").font(.headline)
            Text(fresh ? resources.pressureDetail : "No fresh sample is available. Readings resume when TripWire can sample again after sleep or a delay; an old reading is not the current state.")
            if let date = resources.pressureObservedAt { Text("Last measured: \(date.formatted(date: .abbreviated, time: .standard))").font(.caption).foregroundStyle(.secondary) }
            Text(fresh && [.warning, .critical].contains(resources.pressure) ? "macOS reports memory demand is high. In Activity Monitor’s Memory tab, sort by Memory and review the largest apps. Close work you no longer need; TripWire does not terminate apps." : "The RAM number and swap graph are separate measurements. RAM can contain useful cache; a high used amount alone does not establish pressure.")
            Button("Open Activity Monitor") {
                NSWorkspace.shared.open(URL(fileURLWithPath: "/System/Applications/Utilities/Activity Monitor.app"))
            }
            Button("Done") { showPressureDetails = false }
        }.font(.callout).padding(18).frame(width: 390).fixedSize(horizontal: false, vertical: true)
    }

    private var selectionLabel: String {
        if showReports {
            guard let key = selectedIdentity else { return "ALL AGENTS · \(hooks.identities.count) OBSERVED IDENTITIES" }
            return hooks.identities.first { $0.identity == key }?.label ?? "SELECTED SESSION · OUTSIDE WINDOW"
        }
        if let key = selectedApp { return appResources.readings.first { $0.id == key }?.name ?? "APP NOT OBSERVED" }
        return appResources.readings.isEmpty ? "LOCAL RESOURCES / ACTION REPORTS" : appResources.readings.map(\.name).joined(separator: " · ")
    }

    private func activityInstrument(now: Date) -> some View {
        let selected = hooks.selecting(selectedIdentity)
        let points = hookHistory.points(for: selectedIdentity)
        return
            VStack(alignment: .leading, spacing: 2) {
                if showReports {
                    instrument(title: "AI / ACTION REPORTS ↗", value: selected.feedTitle(at: now),
                               footer: selected.hasRecentReport(at: now) ? selected.lifecycle(at: now) : "SOURCE STATUS / DETAILS ↗", color: amber,
                               points: selected.hasRecentReport(at: now) ? points : [], now: now, limit: max(1, points.compactMap(\.value).max() ?? 1),
                               missing: selected.truncated ? "REPORT WINDOW TRUNCATED" : !selected.hasRecentReport(at: now) ? "NO CURRENT ACTIVITY COVERAGE" : nil,
                               markers: selected.hasRecentReport(at: now) ? selected.reports : [], detail: selected.latestEvent.map { "LAST: " + $0.actionDescription } ?? "NO SOURCE REPORT RECEIVED",
                               focus: .reports(selectedIdentity), openDetails: { inspect(selectedIdentity) })
                } else {
                    localAppInstrument(now: now)
                }
                Menu {
                    Button("Local CPU & memory · all recognized AI apps") { showReports = false; selectedApp = nil }
                    ForEach(appResources.readings) { app in
                        Button("Local resources · \(app.name)") { showReports = false; selectedApp = app.id }
                    }
                    Divider()
                    Button("Action reports · all identities") { showReports = true; selectedIdentity = nil }
                    ForEach(hooks.identities, id: \.identity) { agent in
                        Button("\(agent.label) · \(agent.state(at: now))") { showReports = true; selectedIdentity = agent.identity }
                    }
                    Divider()
                    Button("Inspect local resource measurements") { inspectResources() }
                    Button("Inspect reports and source status") { inspect(selectedIdentity) }
                    Text("Adapters: Codex · Claude Code · Cursor · Generic v1")
                    Text("Live coverage requires approved setup and actual reports")
                } label: {
                    Text(selectionLabel)
                        .font(.system(size: compact ? 11 : 9, design: .monospaced)).lineLimit(1)
                }.menuStyle(.borderlessButton).foregroundStyle(amber)
                .help("Choose local app resource use or reported agent actions")
            }.frame(maxWidth: .infinity, alignment: .leading)
                .help(showReports ? "Application-reported tool/lifecycle metadata. Reports can be omitted or forged and do not prove host effects or approval granted. Current state expires after 30 seconds. Local hooks do not cover cloud-orchestrated chats. \(selected.lastEventText(at: now)). \(selected.error ?? "")" : "Measured local resources for recognized AI desktop apps and observed descendants. Includes interface rendering and local tool execution. Cloud model compute, GPU use, tokens and individual prompts are not measured. Click for process scope, sample time and limitations.")
    }

    private func localAppInstrument(now: Date) -> some View {
        let fresh = appResources.isFresh(at: now)
        let app = selectedApp.flatMap { key in appResources.readings.first { $0.id == key } }
        let cpu = fresh ? (selectedApp == nil ? appResources.totalCPU : app?.cpuPercent) : nil
        let memory = fresh ? (selectedApp == nil ? appResources.totalMemory : app?.memoryBytes) : nil
        let count = selectedApp == nil ? appResources.readings.reduce(0) { $0 + $1.processCount } : (app?.processCount ?? 0)
        let limited = selectedApp == nil ? appResources.limited : (app?.limited ?? true)
        let points = selectedApp.map { appResources.perApp[$0]?.points ?? [] } ?? appResources.history.points
        let scale = min(100, max(5, ceil((points.compactMap(\.value).max() ?? 0) / 5) * 5))
        let value = cpu.map { String(format: "%@%.2f%% CPU", limited ? "≥" : "", $0) } ?? "CPU UNKNOWN"
        let missing = appResources.error != nil ? "SOURCE UNAVAILABLE" : !fresh ? "WAITING FOR SAMPLE" : count == 0 ? "NO APP PROCESS MEASURED" : cpu == nil ? "MEASURING CPU INTERVAL" : nil
        return instrument(title: vertical ? "AI / LOCAL CPU ↗" : "AI APPS / LOCAL CPU ↗", value: value,
                       footer: memory.map { String(format: "RAM ~%.2f GiB · %d PROCS", $0 / 1_073_741_824, count) } ?? "APP MEMORY UNKNOWN",
                       color: amber, points: points, now: now, limit: scale, missing: missing,
                       detail: String(format: vertical ? "60s · HOST CPU · MAX %.0f%%" : "60s · HOST SHARE · SCALE %.0f%%", scale), focus: .appCPU(selectedApp), openDetails: inspectResources)
    }

    private func capture() -> MetricCapture {
        MetricCapture(date: Date(), resources: resources, apps: appResources, hooks: hooks, hookHistory: hookHistory)
    }

    private func instrument(title: String, value: String, footer: String, color: Color,
                            points: [MetricPoint], now: Date, limit: Double, missing: String?, markers: [AgentReceipt] = [], detail: String? = nil, focus: MetricFocus, openDetails: (() -> Void)? = nil) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Button {
                if let openDetails { openDetails() }
                else {
                    let snapshot = capture()
                    inspectRange(MetricInspection(focus: focus, interval: DateInterval(start: snapshot.date.addingTimeInterval(-60), end: snapshot.date), capture: snapshot))
                }
            } label: {
            VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.system(size: compact ? 15 : 10, weight: .bold, design: .monospaced))
                .foregroundStyle(color.opacity(0.85)).lineLimit(1)
            Text(value).font(.system(size: compact ? 20 : 18, weight: .semibold, design: .monospaced))
                .foregroundStyle(color).monospacedDigit().lineLimit(1).minimumScaleFactor(0.8)
            }
            }.buttonStyle(.plain)
            SelectableMetricChart(series: [MetricSeries(points: points, color: color)], maximum: limit, markers: markers,
                                  live: live, focus: focus, capture: capture, inspect: inspectRange)
                .frame(height: compact ? 42 : 30)
                .overlay(alignment: .center) {
                    if let missing {
                        Text(missing).font(.system(size: compact ? 12 : 9, weight: .medium, design: .monospaced))
                            .foregroundStyle(color).padding(3).background(.black.opacity(0.85)).lineLimit(1).allowsHitTesting(false)
                    }
                }
            Text(footer).font(.system(size: compact ? 10 : 8, design: .monospaced))
                .foregroundStyle(Color.white.opacity(0.6)).lineLimit(1)
            if let detail {
                Text(detail).font(.system(size: compact ? 11 : 9, design: .monospaced))
                    .foregroundStyle(color.opacity(0.85)).lineLimit(1)
            }
        }.frame(maxWidth: .infinity, alignment: .leading)

    }
}

struct RetroTrace: View {
    var points: [MetricPoint]
    var now: Date
    var maximum: Double
    var color: Color
    var markers: [AgentReceipt]
    var live: Bool
    var drawsBackground = true
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    var body: some View {
        TimelineView(.animation(minimumInterval: reduceMotion ? 1 : 1.0 / 30, paused: !live || (points.isEmpty && markers.isEmpty))) { timeline in
          Canvas { context, size in
            let now = live ? timeline.date : now
            let inset: CGFloat = 1
            let width = max(0, size.width - 2 * inset), height = max(0, size.height - 2 * inset)
            var grid = Path()
            for fraction in [0.0, 0.25, 0.5, 0.75, 1.0] {
                let y = inset + height * fraction
                grid.move(to: CGPoint(x: inset, y: y)); grid.addLine(to: CGPoint(x: inset + width, y: y))
            }
            for seconds in stride(from: 0.0, through: 60, by: 10) {
                let x = inset + width * seconds / 60
                grid.move(to: CGPoint(x: x, y: inset)); grid.addLine(to: CGPoint(x: x, y: inset + height))
            }
            if drawsBackground { context.stroke(grid, with: .color(color.opacity(0.16)), lineWidth: 0.5) }
            var trace = Path(), previous: MetricPoint?
            for point in points {
                let age = now.timeIntervalSince(point.timestamp)
                guard (0...60).contains(age), let value = point.value, value.isFinite, (0...maximum).contains(value) else { previous = nil; continue }
                let position = CGPoint(x: inset + MetricPlot.x(timestamp: point.timestamp, now: now, width: width), y: inset + height * (1 - value / maximum))
                if let last = previous, MetricPlot.canJoin(previous: last, current: point) {
                    trace.addLine(to: position)
                } else { trace.move(to: position) }
                previous = point
            }
            // Only this small Canvas scrolls at up to 30 fps; measured values stay at 1 Hz.
            context.stroke(trace, with: .color(color.opacity(0.17)), lineWidth: 4)
            context.stroke(trace, with: .color(color), lineWidth: 1.3)
            // Only evidence-backed adapter markers; no host-event substitution.
            // Bound paint work even if a future adapter reports a large burst.
            for marker in markers.suffix(128) {
                let age = now.timeIntervalSince(marker.timestamp)
                guard (0...60).contains(age) else { continue }
                let x = inset + width * (1 - age / 60)
                guard let kind = marker.kind else { continue }
                let lane = AgentActivityKind.allCases.firstIndex(of: kind) ?? 0
                let y = inset + height * (Double(lane) + 0.5) / Double(AgentActivityKind.allCases.count)
                context.draw(Text(kind.rawValue).font(.system(size: 8, weight: .bold, design: .monospaced)).foregroundColor(color), at: CGPoint(x: x, y: y))
            }
          }.background(drawsBackground ? .black.opacity(0.45) : .clear).accessibilityHidden(true)
        }
    }
}
