import SwiftUI
import TripWireCore

/// A compact presentation of the same measured samples, never a separate source.
struct MiniResourceReadings {
    var cpu: String
    var ram: String
    var appCPU: String
    init(resources: ResourceMetrics, apps: AppResourceMetrics, now: Date) {
        let fresh = resources.isFresh(at: now)
        cpu = (fresh ? resources.cpu.points.last?.value : nil).map { String(format: "%.1f%%", $0) } ?? "UNKNOWN"
        ram = (fresh ? resources.latestRAM : nil).flatMap { usage in
            usage.usedEstimateBytes.map { String(format: "%.1f/%.0f GiB", Double($0) / 1_073_741_824, Double(usage.totalBytes) / 1_073_741_824) }
        } ?? "UNKNOWN"
        appCPU = (apps.isFresh(at: now) ? apps.totalCPU : nil).map { String(format: "%@%.1f%%", apps.limited ? "≥" : "", $0) } ?? "UNKNOWN"
    }
}

struct MiniMetricsStrip: View {
    var resources: ResourceMetrics
    var apps: AppResourceMetrics
    var hooks: AgentActivityView
    var hookHistory: AgentActivityHistory
    var live: Bool
    var inspectApps: () -> Void
    var inspectRange: (MetricInspection) -> Void
    @State private var showMemory = false
    private let cyan = Color(red: 0.05, green: 0.91, blue: 1)
    private let green = Color(red: 0.35, green: 1, blue: 0.68)
    private let amber = Color(red: 1, green: 0.76, blue: 0.3)

    var body: some View {
        let readings = MiniResourceReadings(resources: resources, apps: apps, now: Date())
        VStack(alignment: .leading, spacing: 2) {
            row("CPU", value: readings.cpu, color: green, points: resources.cpu.points, maximum: 100, focus: .hostCPU) {
                let snapshot = capture()
                inspectRange(MetricInspection(focus: .hostCPU, interval: DateInterval(start: snapshot.date.addingTimeInterval(-60), end: snapshot.date), capture: snapshot))
            }.help("Host CPU across all cores, 0–100%. The trace covers 60 seconds; click or drag to inspect. Missing or interrupted samples remain unknown.")
            Button { showMemory = true } label: {
                HStack(spacing: 4) {
                    Text("RAM").frame(width: 54, alignment: .leading)
                    Text(readings.ram).monospacedDigit()
                    Spacer(minLength: 0)
                    Image(systemName: "info.circle")
                }.foregroundStyle(cyan).frame(height: 17)
            }.buttonStyle(.plain).accessibilityLabel("RAM used estimate: \(readings.ram). Inspect memory details")
                .help("Used RAM estimate excluding file-backed cache. Click for memory pressure, source and limitations.")
                .popover(isPresented: $showMemory) {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Memory · \(readings.ram)").font(.headline)
                        Text("Pressure: \(resources.isFresh(at: Date()) ? resources.pressure.rawValue : "UNKNOWN")")
                        Text(resources.isFresh(at: Date()) ? resources.pressureDetail : "No fresh resource sample is available.")
                        Text("Used RAM is an estimate from macOS VM counters that excludes file-backed cache. High occupancy alone is not memory pressure.")
                        Text(resources.latestRAM?.breakdown ?? "RAM breakdown unavailable.").font(.caption)
                    }.padding(18).frame(width: 310).textSelection(.enabled)
                }
            row("AI CPU", value: readings.appCPU, color: amber, points: apps.history.points,
                maximum: max(5, (apps.history.points.compactMap(\.value).max() ?? 0).rounded(.up)), focus: .appCPU(nil), action: inspectApps)
                .help("Measured local CPU for recognized AI desktop apps and observed descendants. ≥ marks partial process visibility. Cloud compute, GPU usage and individual prompt attribution are not measured. Click the value for app details or the 60-second trace to investigate.")
        }.font(.system(size: 13, weight: .semibold, design: .monospaced))
    }

    private func row(_ title: String, value: String, color: Color, points: [MetricPoint], maximum: Double,
                     focus: MetricFocus, action: @escaping () -> Void) -> some View {
        HStack(spacing: 4) {
            Button(action: action) {
                HStack(spacing: 4) {
                    Text(title).frame(width: 54, alignment: .leading)
                    Text(value).monospacedDigit().frame(width: 58, alignment: .leading)
                }.foregroundStyle(color).fixedSize(horizontal: true, vertical: false)
            }.buttonStyle(.plain).accessibilityLabel("\(title): \(value). Inspect details")
            SelectableMetricChart(series: [MetricSeries(points: points, color: color)], maximum: maximum,
                                  live: live, focus: focus, capture: capture, inspect: inspectRange)
                .frame(height: 15)
        }.frame(height: 17)
    }
    private func capture() -> MetricCapture {
        MetricCapture(date: Date(), resources: resources, apps: apps, hooks: hooks, hookHistory: hookHistory)
    }
}
