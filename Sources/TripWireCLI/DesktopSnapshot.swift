import Foundation
import TripWireCore
import TripWireCollectors

struct DesktopSnapshot: Encodable {
    var schemaVersion = 1
    var platform = HostPlatform.current
    var sampledAt: String
    var coverage: String
    var findingsCount: Int
    var inventoryTruncated: Bool
    var findingsTruncated: Bool
    var sensors: [SensorHealth]
    var findings: [Finding]
    var inventory: [InventoryRecord]
    var events: [EvidenceEvent]
    var tripwires: [TripwireRule]
    var assessments: [FindingAssessment]
    var riskCounts: [String: Int]
    var reviewedCount: Int
    init(store: EventStore) throws {
        let view = try StoreView(store: store)
        tripwires = view.tripwires
        assessments = view.findings.prefix(1000).map { view.assessment(for: $0) }
        riskCounts = Dictionary(uniqueKeysWithValues: view.riskCounts.map { ($0.key.rawValue, $0.value) })
        reviewedCount = view.findings.filter { view.assessment(for: $0).status != .open }.count
        sampledAt = view.sampledAt; coverage = view.coverage; findingsCount = view.findings.count
        inventoryTruncated = view.inventory.count > 1000; findingsTruncated = view.findings.count > 1000
        let recorded = Dictionary(view.sensors.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        sensors = CollectorRegistry.make(storeURL: store.url).map { collector in
            if let existing = recorded[collector.descriptor.id] { return existing }
            if let unavailable = collector as? UnavailableCollector {
                return SensorHealth(descriptor: collector.descriptor, state: unavailable.state, visibility: .unavailable, detail: unavailable.reason)
            }
            return SensorHealth(descriptor: collector.descriptor, detail: "Not started. Start monitoring for this source; scope limitations remain.")
        }
        let registeredIDs = Set(sensors.map(\.id))
        sensors += view.sensors.filter { !registeredIDs.contains($0.id) }
        findings = Array(view.findings.prefix(1000)); inventory = Array(view.inventory.sorted { $0.lastSeen > $1.lastSeen }.prefix(1000)); events = view.events
    }
}
