import Foundation
import Combine
import TripWireCore
import TripWireCollectors

@MainActor final class DashboardModel: ObservableObject {
    @Published var view: StoreView?
    @Published private(set) var agents = AgentActivityView()
    @Published var metricInspection: MetricInspection?
    @Published var appResourceSnapshot = AppResourceMetrics()
    @Published private(set) var agentSources: [AgentSourceSetup] = []
    @Published private(set) var readError: String?
    @Published private(set) var collectionError: String?
    @Published private(set) var running = false
    @Published private(set) var sampling = false
    @Published private(set) var stopping = false
    @Published var route: DashboardRoute = .overview
    @Published var configurationError: String?
    @Published private var dismissedAlerts = Set<String>()
    var store: EventStore?
    let storeURL: URL
    private let collectors: [any Collector]
    private var task: Task<Void, Never>?
    private var refreshPending = false
    private var refreshVersion = 0
    var error: String? { readError ?? collectionError }

    init(storeURL: URL? = nil) {
        umask(0o077)
        let args = CommandLine.arguments
        let index = args.firstIndex(of: "--db")
        self.storeURL = storeURL ?? index.flatMap { $0 + 1 < args.count ? URL(fileURLWithPath: args[$0 + 1]) : nil } ?? EventStore.defaultURL
        collectors = CollectorRegistry.make(storeURL: self.storeURL)
        refresh()
    }
    func refresh() {
        refreshVersion += 1
        agentSources = AgentIntegrationProbe.inspect(executable: AgentIntegrationProbe.defaultExecutable)
        do {
            if store == nil { store = try EventStore(url: storeURL, access: .readOnly) }
            if let store { view = try StoreView(store: store); agents = try store.readSnapshot { try store.agentActivity() } }
            readError = nil
        } catch {
            view = nil; agents = AgentActivityView(error: "Agent evidence could not be read")
            readError = "Stored evidence could not be read: \(error)"
        }
    }
    /// Periodic SQLite decoding/integrity work must not stall chart rendering.
    /// Each worker owns its read-only connection; overlapping timer reads coalesce.
    func refreshInBackground() {
        guard !refreshPending else { return }
        refreshPending = true
        let version = refreshVersion, url = storeURL, executable = AgentIntegrationProbe.defaultExecutable
        Task {
            let result = await Task.detached(priority: .utility) {
                let sources = AgentIntegrationProbe.inspect(executable: executable)
                let read = Result {
                    let reader = try EventStore(url: url, access: .readOnly)
                    return (try StoreView(store: reader), reader, try reader.readSnapshot { try reader.agentActivity() })
                }
                return (read, sources)
            }.value
            refreshPending = false
            guard version == refreshVersion else { return }
            agentSources = result.1
            switch result.0 {
            case .success(let snapshot): view = snapshot.0; store = snapshot.1; agents = snapshot.2; readError = nil
            case .failure(let error): view = nil; agents = AgentActivityView(error: "Agent evidence could not be read"); readError = "Stored evidence could not be read: \(error)"
            }
        }
    }
    func begin(once: Bool) {
        guard !sampling else { return }
        let writer: EventStore
        do { writer = try EventStore(url: storeURL) }
        catch { collectionError = String(describing: error); return }
        sampling = true; running = !once; stopping = false; collectionError = nil
        task = Task {
            let monitor = Monitor(store: writer)
            defer {
                do { try monitor.stop() } catch { collectionError = "Could not record the monitoring stop: \(error)" }
                sampling = false; running = false; stopping = false; refreshInBackground()
            }
            do {
                repeat {
                    try await monitor.sample(continuousFiles: !once); refreshInBackground()
                    if once || Task.isCancelled { break }
                    try await Task.sleep(nanoseconds: 15_000_000_000)
                } while !Task.isCancelled
            } catch is CancellationError {} catch { collectionError = String(describing: error) }
        }
    }
    func stop() { stopping = true; task?.cancel() }
    var tripwireAlerts: [Finding] { (view?.findings ?? []).filter { $0.ruleID.hasPrefix("user-tripwire:") } }
    var alert: Finding? { tripwireAlerts.first { !dismissedAlerts.contains($0.id) && view?.assessment(for: $0).status == .open } }
    var openFindings: [Finding] { view?.openFindings ?? [] }
    func review(_ finding: Finding, level: RiskLevel, status: FindingReviewStatus, reason: String, expectedReviewID: String?) throws {
        try EventStore(url: storeURL).reviewFinding(id: finding.id, level: level, status: status, reason: reason, expectedReviewID: expectedReviewID)
        refresh()
    }
    func dismissAlert(_ finding: Finding) { dismissedAlerts.insert(finding.id) }
    @discardableResult func saveTripwire(_ rule: TripwireRule) -> Bool {
        do { try EventStore(url: storeURL).saveTripwire(rule); configurationError = nil; refresh(); return true }
        catch { configurationError = String(describing: error); return false }
    }
    func deleteTripwire(_ rule: TripwireRule) {
        do { try EventStore(url: storeURL).deleteTripwire(id: rule.id); configurationError = nil; refresh() }
        catch { configurationError = String(describing: error) }
    }
    func open(_ metric: DashboardMetric) { route = metric.destination }
    var hasSample: Bool { view?.sampledAt != nil && view?.sampledAt != "NEVER" }
    func count(_ value: Int?) -> String { guard hasSample, let value else { return "—" }; return String(value) }

    var sensors: [SensorHealth] {
        let saved = Dictionary(uniqueKeysWithValues: (view?.sensors ?? []).map { ($0.id, $0) })
        let registered = collectors.map { collector -> SensorHealth in
            if let health = saved[collector.descriptor.id] { return health.effective() }
            if let unavailable = collector as? UnavailableCollector {
                return SensorHealth(descriptor: collector.descriptor, state: unavailable.state, visibility: .unavailable, detail: unavailable.reason)
            }
            return SensorHealth(descriptor: collector.descriptor)
        }
        return registered + (saved[OpenEventBridge.id].map { [$0.effective(staleAfter: 10)] } ?? [])
    }
    var fileEventsReporting: Bool {
        sensors.contains { $0.id == OpenEventBridge.id && SensorPresentation($0).kind == .reporting }
    }
    var reporting: Int { checkSummary.reporting.count }
    var checkSummary: CheckSummary { CheckSummary(sensors: sensors, running: running, sampling: sampling, readError: readError) }
    var unavailable: Int { sensors.filter { SensorPresentation($0).kind == .unavailable }.count }
    var attention: Int { checkSummary.failed.count + checkSummary.waiting.count }
    var monitoringTitle: String {
        if readError != nil { return "Evidence unavailable" }
        if stopping { return "Stopping monitoring…" }
        if running { return "Monitoring is on" }
        if sampling { return "Taking a snapshot…" }
        if reporting > 0 { return "Recent sensor reports from another session" }
        return hasSample ? "Monitoring is off" : "Ready for the first check"
    }
    var monitoringExplanation: String {
        if readError != nil { return "Counts are unknown until the store can be read. Existing evidence has not been replaced." }
        if stopping { return "Finishing the current check and recording that collection has stopped." }
        if running { return "AI open-file snapshots target 2-second intervals; other inventories pause 15 seconds between rounds. Short-lived activity can be missed." }
        if sampling { return "One check of implemented sources. A snapshot stops when that round finishes." }
        if reporting > 0 { return "This window is viewing the shared store. Recent heartbeats are available; stop or manage collection from the session that started it." }
        return "Start monitoring for repeated checks, or take a snapshot for one check. Unavailable sensors require further implementation."
    }
    func evidence(for finding: Finding) throws -> FindingEvidence {
        guard let store else { throw TripWireError.message("Event store unavailable") }
        return try FindingEvidence(finding: finding) { try store.event(id: $0) }
    }
    func event(id: String) throws -> EvidenceEvent? {
        guard let store else { throw TripWireError.message("Event store unavailable") }
        return try store.event(id: id)
    }
}
