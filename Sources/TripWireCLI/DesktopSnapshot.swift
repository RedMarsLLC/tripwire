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
    init(store: EventStore) throws {
        let view = try StoreView(store: store)
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
        findings = Array(view.findings.prefix(1000)); inventory = Array(view.inventory.sorted { $0.lastSeen > $1.lastSeen }.prefix(1000)); events = view.events
    }
}
