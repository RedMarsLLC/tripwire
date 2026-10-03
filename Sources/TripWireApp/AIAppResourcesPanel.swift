import SwiftUI
import TripWireCore

struct AIAppResourcesPanel: View {
    @EnvironmentObject var model: DashboardModel
    var metrics: AppResourceMetrics
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("AI apps · local resource use").font(.title2.bold())
            Text("Measured CPU and memory for recognized running desktop apps, their bundled helpers and observed child processes. Desktop rendering, local tools and other app work contribute even when no action hook is available.")
            Text("Sample captured: \(TimeText.iso(metrics.lastSample)). The overlay samples live once per second while visible.").font(.caption).foregroundStyle(.secondary)
            if let error = metrics.error { Text(error).foregroundStyle(.orange) }
            if metrics.readings.isEmpty { Text("No app measurements in this snapshot. This does not establish that no AI is in use.").foregroundStyle(.secondary) }
            ForEach(metrics.readings) { app in
                VStack(alignment: .leading, spacing: 8) {
                    Text(app.name).font(.title3.bold())
                    Text(app.cpuPercent.map { String(format: "CPU: %@%.2f%% of host capacity", app.limited ? "at least " : "", $0) } ?? "CPU: waiting for a continuous interval")
                    Text(app.memoryBytes.map { String(format: "Memory footprint sum: %.2f GiB", $0 / 1_073_741_824) } ?? "Memory: unavailable")
                    Text("\(app.processCount) measured processes · \(app.id)").font(.caption.monospaced())
                    if app.limited { Text("Partial interval or process visibility. Unmeasured work is unknown; counts and resource sums may be lower bounds.").foregroundStyle(.orange).font(.caption) }
                }.padding().frame(maxWidth: .infinity, alignment: .leading).cyberPanel().clipShape(RoundedRectangle(cornerRadius: 8))
            }
            Button("Inspect agent action reports and source status") { model.route = .agents(nil) }
            Text("CPU is normalized over all logical cores (100% = the entire host). Memory is a sum of OS process footprints and may include shared accounting. App recognition uses bundle metadata; process grouping uses exact bundle paths and observed parent relationships. This is resource association, not security attestation or attribution to an individual prompt.")
                .font(.callout).foregroundStyle(.secondary)
            Text("Cloud model computation, token usage, GPU work, browser-only AI sessions and unrecognized apps are not measured here. Short-lived or inaccessible processes can be missed. CPU can remain low while a remote model is working. No prompt contents, process arguments, environment values or transcripts are collected.")
                .font(.callout).foregroundStyle(.secondary)
        }
    }
}
