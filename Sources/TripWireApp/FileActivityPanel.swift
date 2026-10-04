import SwiftUI
import TripWireCore
import TripWireCollectors

struct FileActivityPanel: View {
    @EnvironmentObject var model: DashboardModel
    @State private var search = ""
    @State private var latestOnly = true
    @State private var lookupError: String?

    private var sensor: SensorHealth? { model.view?.sensors.first { $0.id == AIFileAccessCollector.id }?.effective(staleAfter: 10) }
    private var records: [InventoryRecord] {
        (model.view?.inventory ?? []).filter { record in
            [AIFileAccessCollector.id, OpenEventBridge.id].contains(record.collector) && (!latestOnly || inLatestCheck(record)) &&
            (search.isEmpty || ([record.observation.component] + Array(record.observation.attributes.values)).contains { $0.localizedCaseInsensitiveContains(search) })
        }.sorted { $0.lastSeen > $1.lastSeen }
    }
    private func inLatestCheck(_ record: InventoryRecord) -> Bool {
        if record.collector == OpenEventBridge.id { return (0...60).contains(Date().timeIntervalSince(record.lastSeen)) }
        guard let last = sensor?.lastHeartbeat else { return false }
        return abs(record.lastSeen.timeIntervalSince(last)) < 0.01
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            FileEventSetup()
            Text("File activity observations").font(.title2.bold())
            Text("Inspect held descriptors and scoped file-operation reports, associated processes and the reason for a flag. File contents are never collected.").foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 9) {
                Label("Open-file snapshots · limited visibility", systemImage: "doc.text.magnifyingglass").font(.headline).foregroundStyle(.orange)
                if let sensor, model.readError == nil {
                    Text("\(SensorPresentation(sensor).title) · checked \(TimeText.iso(sensor.lastHeartbeat))").font(.callout.bold())
                    Text(sensor.detail).font(.callout)
                } else { Text("No readable file-watch report yet. Start monitoring to collect open-file metadata.") }
                Text("Checks target 2-second intervals. Short-lived opens, detached/unrecognized agents and protected processes may be missed. Open mode is capability, not proof of a read or write. App association does not prove an AI action.").font(.callout)
                HStack {
                    Button("Collector status →") { model.route = .coverage(.sensor(AIFileAccessCollector.id)) }
                    Button("Full OS audit: requirements →") { model.route = .coverage(.sensor("endpoint-security")) }
                    if !model.sampling { Button("Start monitoring") { model.begin(once: false) } }
                }
            }.padding(16).frame(maxWidth: .infinity, alignment: .leading).cyberPanel().clipShape(RoundedRectangle(cornerRadius: 10))
            HStack {
                TextField("Search file path, app, process or review reason", text: $search).textFieldStyle(.roundedBorder)
                Toggle("Latest snapshots / events in last minute", isOn: $latestOnly).toggleStyle(.checkbox)
            }
            Text("\(records.count) matching records · snapshot rows are held-descriptor metadata; event-feed rows are individual reported operations. Last observed does not mean still open.").font(.caption).foregroundStyle(.secondary)
            if let lookupError { Text(lookupError).foregroundStyle(.orange) }
            if records.isEmpty {
                Text("No matching open-file observations in this view. This does not establish that an agent accessed no files. Turn off Latest check only to inspect retained history.").foregroundStyle(.secondary)
            }
            LazyVStack(alignment: .leading, spacing: 12) {
                ForEach(Array(records.prefix(200))) { record in row(record) }
            }
            if records.count > 200 { Text("Showing the first 200 matches. Refine the search to inspect other paths.").foregroundStyle(.secondary) }
        }
    }
    private func row(_ record: InventoryRecord) -> some View {
        let observation = record.observation, attrs = observation.attributes
        return VStack(alignment: .leading, spacing: 8) {
            Text(observation.component).font(.system(.body, design: .monospaced)).foregroundStyle(accent).textSelection(.enabled)
            Text("\(attrs["associatedApp"] ?? "Unknown app") · PID \(attrs["pid"] ?? "unknown") · \(attrs["openMode"] ?? "Unknown open mode")").font(.headline)
            Text(attrs["operation"] ?? "Descriptor sampled; actual read/write unknown").font(.callout).foregroundStyle(accent)
            Text(attrs["executable"] ?? "Executable unavailable").font(.caption).textSelection(.enabled)
            Text(record.collector == OpenEventBridge.id ? "Source: foreground file-operation report" : "Source: open-descriptor snapshot").font(.caption).foregroundStyle(accent)
            Text("Last observed \(TimeText.iso(record.lastSeen)) · \(inLatestCheck(record) ? "in latest check" : "historical observation")").font(.caption).foregroundStyle(.secondary)
            Text(attrs["associationBasis"] ?? "Association basis unknown").font(.caption).foregroundStyle(.secondary)
            if let reason = attrs["reviewReason"] { Label(reason, systemImage: "exclamationmark.triangle").font(.callout).foregroundStyle(.orange) }
            Button(attrs["reviewReason"] == nil ? "Inspect supporting observation →" : "Why flagged / supporting observation →") {
                lookupError = nil
                do {
                    if let event = try model.store?.latestEvent(collector: record.collector, key: observation.key) {
                        if let finding = model.view?.findings.first(where: { $0.eventIDs.contains(event.id) }) { model.route = .findings(finding.id) }
                        else { model.route = .event(event.id) }
                    } else { lookupError = "The supporting observation is unavailable. Retained metadata is shown above." }
                } catch { lookupError = "The supporting observation could not be read: \(error)" }
            }
        }.padding(16).frame(maxWidth: .infinity, alignment: .leading).cyberPanel().clipShape(RoundedRectangle(cornerRadius: 10))
    }
}
