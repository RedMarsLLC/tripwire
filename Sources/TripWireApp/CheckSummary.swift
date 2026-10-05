import Foundation
import TripWireCore
import TripWireCollectors

/// Inventory checks are defined by TripWire's registry, not discovered threats,
/// devices or a percentage of everything this Mac can do.
struct CheckSummary {
    let available: [SensorHealth]
    let notImplemented: [SensorHealth]
    let optional: [SensorHealth]
    let reporting: [SensorHealth]
    let failed: [SensorHealth]
    let waiting: [SensorHealth]
    let running: Bool
    let sampling: Bool
    let readError: String?

    init(sensors: [SensorHealth], running: Bool, sampling: Bool, readError: String?, now: Date = Date()) {
        self.running = running; self.sampling = sampling; self.readError = readError
        let sources = sensors.map { $0.effective(at: now, staleAfter: [AIFileAccessCollector.id, OpenEventBridge.id].contains($0.id) ? 10 : 90) }
        let missing = Set(CollectorRegistry.unavailable.map { $0.descriptor.id })
        notImplemented = sources.filter { missing.contains($0.id) }
        optional = sources.filter { $0.id == "canaries" && $0.state == .stopped && (!$0.initialized || $0.visibility == .unavailable) }
        let excluded = missing.union(optional.map(\.id))
        available = sources.filter { !excluded.contains($0.id) }
        reporting = readError == nil ? available.filter { [.active, .degraded].contains($0.state) && [.available, .limited].contains($0.visibility) } : []
        failed = readError == nil ? available.filter { [.error, .permissionMissing, .dataLossDetected, .unsupported].contains($0.state) || ($0.state != .stopped && [.unknown, .unavailable, .notObservable].contains($0.visibility)) } : []
        let accounted = Set(reporting.map(\.id) + failed.map(\.id))
        waiting = available.filter { !accounted.contains($0.id) }
    }
    var paused: Bool { readError == nil && !running && !sampling && reporting.isEmpty && failed.isEmpty }
    var value: String {
        if readError != nil { return "UNREADABLE" }
        if paused { return "PAUSED" }
        if reporting.isEmpty && sampling { return "STARTING" }
        return "\(reporting.count) LIVE"
    }
    var countNote: String { "\(available.count) available checks · details" }
    var headline: String {
        if readError != nil { return "CAN’T READ CHECK RESULTS ↗" }
        if !failed.isEmpty { return "\(failed.count) CHECK\(failed.count == 1 ? "" : "S") NEED\(failed.count == 1 ? "S" : "") ATTENTION ↗" }
        if paused { return "CHECKS PAUSED · START ↗" }
        if reporting.isEmpty && sampling { return "CHECKS STARTING…" }
        if !waiting.isEmpty { return "\(waiting.count) CHECK\(waiting.count == 1 ? "" : "S") NOT REPORTING ↗" }
        if reporting.contains(where: { $0.id == OpenEventBridge.id }) { return "FILE OPEN EVENTS · LIMITED ↗" }
        if reporting.contains(where: { $0.id == AIFileAccessCollector.id }) { return "FILE WATCH: SNAPSHOTS ↗" }
        if notImplemented.contains(where: { $0.id == "endpoint-security" }) { return "AI FILE ACCESS NOT MONITORED ↗" }
        return "CHECKS LIVE · VIEW SCOPE ↗"
    }
    var focus: SensorScope {
        if readError != nil || paused { return .all }
        if !failed.isEmpty || !waiting.isEmpty { return .attention }
        if reporting.contains(where: { $0.id == OpenEventBridge.id }) { return .sensor(OpenEventBridge.id) }
        if reporting.contains(where: { $0.id == AIFileAccessCollector.id }) { return .sensor(AIFileAccessCollector.id) }
        if notImplemented.contains(where: { $0.id == "endpoint-security" }) { return .sensor("endpoint-security") }
        return .all
    }
    var destination: DashboardRoute { focus == .sensor(AIFileAccessCollector.id) ? .files : .coverage(focus) }
    var explanation: String {
        if let readError { return "The evidence store cannot be read: \(readError). Retry reading it in the dashboard. Counts are unavailable." }
        if !failed.isEmpty { return failed.map { "\($0.descriptor.name): \($0.detail)" }.joined(separator: "\n") }
        if paused { return "Security inventory checks are stopped. Click Start to run them while TripWire is open. Live CPU/RAM charts run separately and do not mean security monitoring is on." }
        if reporting.isEmpty && sampling { return "Waiting for this monitoring round to produce its first reports." }
        if !waiting.isEmpty { return "No current report from: " + waiting.map { $0.descriptor.name }.joined(separator: ", ") + ". Open details to see the last check and restart or retry the source." }
        if reporting.contains(where: { $0.id == AIFileAccessCollector.id }) { return "Open File Activity to inspect file paths, holding processes, associated AI apps and sensitive-location findings. Open-file snapshots target 2-second intervals; brief opens and actual reads/writes are not audited. For brief operations, open Tripwires → File monitoring and enable the in-app monitor with macOS approval. The diagnostic source remains limited; a native Endpoint Security provider is not deployed." }
        return "The current build has no OS event collector for individual file accesses or reliable agent attribution. This requires implementation and an approved Endpoint Security deployment; starting checks or changing a setting cannot enable it."
    }
    var catalogExplanation: String {
        "TripWire defines these checks in its collector registry. \(available.count) are available in this build; \(notImplemented.count) features are not implemented; \(optional.count) optional check(s) are not configured. The live count excludes those unavailable/optional entries. It counts recent scoped reports, not threats, AI agents, devices or a coverage percentage. CPU/RAM charts run independently."
    }
}
