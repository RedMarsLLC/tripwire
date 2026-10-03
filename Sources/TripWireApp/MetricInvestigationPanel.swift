import SwiftUI
import TripWireCore

struct MetricInvestigationPanel: View {
    @EnvironmentObject var model: DashboardModel
    var inspection: MetricInspection
    @State private var interval: DateInterval
    @State private var evidence: EvidenceWindow?
    @State private var evidenceError: String?
    init(inspection: MetricInspection) {
        self.inspection = inspection
        _interval = State(initialValue: inspection.interval)
    }
    private var focusedPoints: [MetricPoint] { inspection.primary }
    private var frames: [AppResourceFrame] { inspection.capture.apps.frames.filter { interval.contains($0.timestamp) } }
    private var appIDs: [String] { Set(frames.flatMap { $0.readings.map(\.id) }).sorted {
        appPeak($0) > appPeak($1)
    } }
    private func appReadings(_ id: String) -> [AppResourceReading] { frames.flatMap { $0.readings.filter { $0.id == id } } }
    private func appPeak(_ id: String) -> Double { appReadings(id).compactMap(\.cpuPercent).max() ?? -1 }
    private var graphSeries: [MetricSeries] {
        if inspection.focus == .swap {
            return [MetricSeries(points: focusedPoints, color: .cyan), MetricSeries(points: inspection.capture.resources.swapOut.points, color: .orange)]
        }
        return [MetricSeries(points: focusedPoints, color: .cyan)]
    }
    private var scale: Double { inspection.focus == .hostCPU ? 100 : max(1, graphSeries.flatMap { $0.points.compactMap(\.value) }.max() ?? 1) }
    private var chartUnit: String {
        switch inspection.focus {
        case .hostCPU, .appCPU: return "% of host CPU"
        case .swap: return "MiB/s"
        case .reports: return "reports / preceding 60s"
        }
    }
    private var selectedSummary: String {
        if inspection.focus == .swap {
            func peak(_ points: [MetricPoint]) -> String {
                MetricSelection.selected(points, in: interval).compactMap(\.value).max().map { String(format: "%.2f MiB/s", $0) } ?? "unknown"
            }
            return "Observed peaks · IN: \(peak(inspection.capture.resources.swapIn.points)) · OUT: \(peak(inspection.capture.resources.swapOut.points))"
        }
        let points = MetricSelection.selected(focusedPoints, in: interval).filter { $0.value != nil }
        guard let peak = points.max(by: { ($0.value ?? 0) < ($1.value ?? 0) }), let value = peak.value else { return "No measured value in this selection" }
        let unit: String
        switch inspection.focus {
        case .hostCPU, .appCPU: unit = "% of host CPU"
        case .swap: unit = "MiB/s swap IN (cyan; OUT is orange)"
        case .reports: unit = "received reports / preceding 60 seconds"
        }
        var partial = false
        if case .appCPU(let id) = inspection.focus {
            partial = frames.flatMap(\.readings).filter { id == nil || $0.id == id }.contains { $0.limited }
        }
        return String(format: "Observed peak: %@%.2f %@ · %@", partial ? "at least " : "", value, unit, stamp(peak.timestamp))
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("\(inspection.focus.title) · investigate selection").font(.title2.bold())
                Spacer()
                Button("Clear investigation") { model.metricInspection = nil; model.route = .overview }
            }
            Text("\(stamp(interval.start)) – \(stamp(interval.end)) · \(String(format: "%.1f", interval.duration)) seconds")
                .font(.headline.monospaced()).textSelection(.enabled)
            Text("Frozen at \(stamp(inspection.capture.date)), local time. Chart and app measurements cover the retained 60-second window; they are not live values.")
                .font(.caption).foregroundStyle(.secondary)
            if case .appCPU(let id?) = inspection.focus {
                Text("Selected app trace: \(inspection.capture.apps.frames.flatMap { $0.readings }.first { $0.id == id }?.name ?? id)").font(.callout)
            }
            if case .reports(let id?) = inspection.focus {
                Text("Selected report identity: \(inspection.capture.hooks.selecting(id).latestEvent?.label ?? id)").font(.callout)
            }
            VStack(alignment: .leading, spacing: 8) {
                Text(selectedSummary).font(.headline).foregroundStyle(.cyan)
                Text(String(format: "Chart scale: 0–%.2f %@", scale, chartUnit)).font(.caption).foregroundStyle(.secondary)
                SelectableMetricChart(series: graphSeries, maximum: scale, live: false, focus: inspection.focus,
                                      capture: { inspection.capture }, inspect: { select($0.interval) })
                    .frame(height: 110)
                    .overlay(alignment: .topLeading) {
                        GeometryReader { geo in
                            let x = MetricPlot.x(timestamp: interval.start, now: inspection.capture.date, width: geo.size.width)
                            Rectangle().fill(Color.cyan.opacity(0.12))
                                .frame(width: geo.size.width * interval.duration / 60).offset(x: x)
                        }.allowsHitTesting(false)
                    }
                HStack {
                    Text("−60s"); Spacer(); Text("Frozen selection · drag to refine"); Spacer(); Text("capture time")
                }.font(.caption.monospaced()).foregroundStyle(.secondary)
                HStack {
                    Button("Widen by 5 seconds") {
                        select(DateInterval(start: max(inspection.capture.date.addingTimeInterval(-60), interval.start.addingTimeInterval(-5)),
                                            end: min(inspection.capture.date, interval.end.addingTimeInterval(5))))
                    }
                    Button("Inspect whole minute") { select(DateInterval(start: inspection.capture.date.addingTimeInterval(-60), end: inspection.capture.date)) }
                }
                Text("Values are sample observations. CPU and swap values summarize the preceding sampling interval, not instantaneous peaks. A spike is not automatically a finding.").font(.caption).foregroundStyle(.secondary)
            }.padding().background(panel).clipShape(RoundedRectangle(cornerRadius: 8))
            HStack(alignment: .top, spacing: 18) {
                summary("HOST CPU", points: inspection.capture.resources.cpu.points, unit: "%")
                summary("RAM USED ESTIMATE", points: inspection.capture.resources.usedRAMGiB.points, unit: "GiB")
                summary("SWAP IN", points: inspection.capture.resources.swapIn.points, unit: "MiB/s")
                summary("SWAP OUT", points: inspection.capture.resources.swapOut.points, unit: "MiB/s")
            }
            let pressure = Set(inspection.capture.resources.pressureHistory.filter { interval.contains($0.timestamp) }.map { $0.state.rawValue }).sorted()
            Text("OS pressure recorded in selection: \(pressure.isEmpty ? "UNKNOWN / NO SAMPLE" : pressure.joined(separator: ", "))").font(.caption).foregroundStyle(.secondary)
            let reasons = MetricSelection.gaps(focusedPoints, in: interval)
            if !reasons.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Sampling gaps in this selection").font(.headline)
                    ForEach(reasons, id: \.self) { Text($0).font(.callout) }
                }.foregroundStyle(.orange)
            }
            Text("Measured AI apps during this window").font(.headline)
            if appIDs.isEmpty { Text("No retained app measurements for this interval. App activity is unknown.").foregroundStyle(.secondary) }
            ForEach(appIDs, id: \.self) { id in
                let readings = appReadings(id)
                let peak = readings.compactMap(\.cpuPercent).max()
                let memory = readings.compactMap(\.memoryBytes).max()
                let partial = readings.contains { $0.limited }
                VStack(alignment: .leading, spacing: 4) {
                    Text(readings.first?.name ?? id).font(.headline)
                    Text("Observed CPU peak: \(peak.map { String(format: "%@%.2f%% of host", partial ? "at least " : "", $0) } ?? "unknown") · memory footprint peak: \(memory.map { String(format: "%.2f GiB", $0 / 1_073_741_824) } ?? "unknown")")
                    Text("\(readings.count) app samples · \(id)\(partial ? " · partial visibility; missing usage is unknown" : "")").font(.caption).foregroundStyle(partial ? .orange : .secondary)
                }.padding(10).frame(maxWidth: .infinity, alignment: .leading).background(panel)
            }
            Text("Only recognized AI apps and observed descendants have resource attribution here. Other host processes, GPU work and remote model compute are not attributed. App activity and nearby events do not establish the cause of a host spike.")
                .font(.callout).foregroundStyle(.secondary)
            evidenceSection
            DisclosureGroup("Exact selected samples and missing intervals") {
                VStack(alignment: .leading, spacing: 5) {
                    ForEach(Array(MetricSelection.selected(focusedPoints, in: interval).enumerated()), id: \.offset) { _, point in
                        Text("\(stamp(point.timestamp)) · \(point.value.map { String(format: "%.3f", $0) } ?? "UNKNOWN")\(point.reason.map { " · " + $0 } ?? "")")
                            .font(.caption.monospaced()).textSelection(.enabled)
                    }
                }.padding(.top, 8)
            }
        }.task(id: interval) { await loadEvidence() }
    }
    private func summary(_ title: String, points: [MetricPoint], unit: String) -> some View {
        let values = MetricSelection.selected(points, in: interval).compactMap(\.value)
        return VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption.bold()).foregroundStyle(.secondary)
            Text(values.max().map { String(format: "%.2f %@ peak", $0, unit) } ?? "UNKNOWN").font(.callout.monospaced())
            Text("\(values.count) measured samples").font(.caption).foregroundStyle(.secondary)
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
    @ViewBuilder private var evidenceSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Recorded activity in the selected window").font(.headline)
            Text("Matched by observation or receipt timestamp, not proven causation. Inventory checks may notice a change after it happened; hooks may omit reports. Each query is capped at 200 observations and 200 findings. An empty result does not prove that nothing happened.")
                .font(.caption).foregroundStyle(.secondary)
            if case .reports = inspection.focus {
                Text("The action chart is a rolling 60-second count. This list uses each report’s receipt time inside the selection, so the list count can differ from the graph.").font(.caption).foregroundStyle(.orange)
            }
            if let evidenceError { Text(evidenceError).foregroundStyle(.orange); Button("Retry evidence query") { Task { await loadEvidence() } } }
            else if let evidence {
                if evidence.eventsTruncated || evidence.findingsTruncated { Text("LIMITED: More records exist than this view can show. Narrow the time range.").foregroundStyle(.orange) }
                Text("Findings recorded in this window: \(evidence.findings.count)\(evidence.findingsTruncated ? "+" : "")").font(.subheadline.bold())
                ForEach(evidence.findings) { finding in
                    Button { model.route = .findings(finding.id) } label: {
                        VStack(alignment: .leading, spacing: 3) {
                            Text("\(stamp(finding.timestamp)) · \(finding.title) ↗").fontWeight(.semibold)
                            Text("Why flagged: \(finding.whyFlagged)").font(.caption).lineLimit(3)
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }.buttonStyle(.plain).padding(8).background(panel)
                }
                if evidence.events.isEmpty { Text("No observations recorded in this window. Collection may have been stopped, unavailable or outside its scope.").foregroundStyle(.secondary) }
                ForEach(evidence.events) { event in
                    Button { model.route = .event(event.id) } label: {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("\(stamp(event.timestamp)) · \(event.observation.component) ↗").fontWeight(.semibold)
                            Text("\(event.sourceCollector) · \(event.eventType) · open original evidence and source limitations").font(.caption).foregroundStyle(.secondary)
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }.buttonStyle(.plain).padding(8).background(panel)
                }
            } else { ProgressView("Reading evidence for this time range…") }
        }
    }
    private func select(_ value: DateInterval) {
        interval = value
        var saved = inspection; saved.interval = value
        model.metricInspection = saved
    }
    private func loadEvidence() async {
        evidence = nil; evidenceError = nil
        let selected = interval, url = model.storeURL
        let result = await Task.detached(priority: .utility) { Result {
            let store = try EventStore(url: url, access: .readOnly)
            return try store.readSnapshot { try store.evidence(in: selected) }
        } }.value
        guard !Task.isCancelled, selected == interval else { return }
        switch result {
        case .success(let records): evidence = records
        case .failure: evidenceError = "Evidence could not be read for this interval. Recorded activity is unknown."
        }
    }
    private func stamp(_ date: Date) -> String { date.formatted(date: .omitted, time: .standard) }
}
