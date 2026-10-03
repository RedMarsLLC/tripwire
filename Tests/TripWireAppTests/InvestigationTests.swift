import XCTest
import TripWireCore
import TripWireCollectors
@testable import TripWireApp

final class InvestigationTests: XCTestCase {
    private var directory: URL!
    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("tripwire-investigation-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }
    override func tearDownWithError() throws { try FileManager.default.removeItem(at: directory) }
    private var url: URL { directory.appendingPathComponent("evidence.sqlite") }
    private let descriptor = SensorDescriptor("fixture", "Synthetic fixture", source: "TEST ONLY", monitors: "Test observations")

    @MainActor func testFirstRunDistinguishesMissingAdaptersFromUnstartedCollectors() async throws {
        let model = DashboardModel(storeURL: url)
        XCTAssertNil(model.readError)
        XCTAssertTrue(model.store?.isReadOnly == true)
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
        XCTAssertFalse(model.hasSample)
        XCTAssertEqual(model.count(0), "—")
        XCTAssertEqual(model.reporting, 0)
        XCTAssertEqual(model.unavailable, CollectorRegistry.unavailable.count)
        for source in CollectorRegistry.unavailable {
            let health = try XCTUnwrap(model.sensors.first { $0.id == source.descriptor.id })
            let presentation = SensorPresentation(health)
            XCTAssertEqual(presentation.kind, .unavailable)
            XCTAssertEqual(presentation.title, "Not available in this build")
        }
        let processes = try XCTUnwrap(model.sensors.first { $0.id == "processes" })
        XCTAssertEqual(SensorPresentation(processes).kind, .unknown)
        XCTAssertEqual(SensorPresentation(processes).title, "Not checked yet")
    }

    @MainActor func testMetricNavigationClearsPreviousFindingAndFilter() async {
        let model = DashboardModel(storeURL: url)
        model.route = .findings("old-finding")
        model.open(.changes)
        XCTAssertEqual(model.route, .events(.changes))
        model.open(.findings)
        XCTAssertEqual(model.route, .findings(nil))
        model.open(.unknowns)
        XCTAssertEqual(model.route, .inventory(.baseline, .unknown))
        model.open(.sockets)
        XCTAssertEqual(model.route, .inventory(.network, .all))
        model.open(.gaps)
        XCTAssertEqual(model.route, .health)
        model.open(.reporting)
        XCTAssertEqual(model.route, .coverage(.reporting))
        model.route = .page(.coverage)
        XCTAssertEqual(model.route, .coverage(.all))
    }

    func testSensorStatusSeparatesLimitedStaleFailedAndUnconfiguredSources() {
        let now = Date()
        var sensor = SensorHealth(descriptor: descriptor, state: .active, visibility: .limited, initialized: true, lastHeartbeat: now, lastSuccess: now)
        XCTAssertEqual(SensorPresentation(sensor).title, "Reporting · limited visibility")
        sensor.visibility = .unknown
        XCTAssertEqual(SensorPresentation(sensor).title, "Reporting · visibility unknown")
        sensor.lastHeartbeat = now.addingTimeInterval(-1000)
        XCTAssertEqual(SensorPresentation(sensor).kind, .stopped)
        XCTAssertFalse(SensorPresentation(sensor).matches(.reporting, id: sensor.id))
        sensor.state = .error; sensor.visibility = .unavailable
        XCTAssertEqual(SensorPresentation(sensor).kind, .attention)
        let canary = SensorHealth(descriptor: CanaryCollector(directory: directory.appendingPathComponent("missing-markers")).descriptor, state: .stopped, visibility: .unavailable)
        XCTAssertEqual(SensorPresentation(canary).title, "Optional canary not configured")
        XCTAssertNotEqual(SensorPresentation(canary).kind, .unavailable)
    }

    @MainActor func testUnreadableStoreNeverLooksEmptyAndCanRecover() async throws {
        try Data("SYNTHETIC INVALID DATABASE".utf8).write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        let model = DashboardModel(storeURL: url)
        XCTAssertNotNil(model.readError)
        XCTAssertNil(model.view)
        XCTAssertEqual(model.count(0), "—")
        XCTAssertEqual(model.monitoringTitle, "Evidence unavailable")
        try FileManager.default.removeItem(at: url)
        let writer = try EventStore(url: url)
        try writer.setMetadata("lastCompletedSample", String(Date().timeIntervalSince1970))
        model.refresh()
        XCTAssertNil(model.readError)
        XCTAssertNotNil(model.view)
        XCTAssertEqual(model.count(model.view?.findings.count), "0")
    }

    @MainActor func testFindingReadsLinkedEvidenceBeyondTheRecentEventWindow() async throws {
        let store = try EventStore(url: url)
        func observation(_ value: String) -> Observation {
            Observation(key: "fixture", eventClass: .persistence, component: "SYNTHETIC launch item", attributes: ["executable": value])
        }
        try store.ingest(CollectorSnapshot(descriptor: descriptor, observations: [observation("/test/original")], complete: true, state: .active, visibility: .limited, detail: "SYNTHETIC TEST"))
        try store.ingest(CollectorSnapshot(descriptor: descriptor, observations: [observation("/test/changed")], complete: true, state: .active, visibility: .limited, detail: "SYNTHETIC TEST"))
        let finding = try XCTUnwrap(store.findings().first)
        for index in 0..<205 {
            let observation = Observation(key: "process", eventClass: .process, component: "SYNTHETIC process", attributes: ["test-value": String(index)])
            try store.ingest(CollectorSnapshot(descriptor: descriptor, timestamp: Date().addingTimeInterval(Double(index + 1)), observations: [observation], complete: false, state: .degraded, visibility: .limited, detail: "SYNTHETIC TEST"))
        }
        let model = DashboardModel(storeURL: url)
        XCTAssertFalse(model.view!.events.contains { finding.eventIDs.contains($0.id) })
        let evidence = try model.evidence(for: finding)
        XCTAssertEqual(evidence.events.map(\.id), finding.eventIDs)
        XCTAssertTrue(evidence.missingIDs.isEmpty)
        XCTAssertEqual(evidence.events.first?.previousState?["executable"], "/test/original")
        XCTAssertEqual(evidence.events.first?.currentState?["executable"], "/test/changed")
        XCTAssertTrue(evidence.explanation(for: finding).contains("what runs automatically"))
        XCTAssertTrue(evidence.explanation(for: finding).contains("Malicious intent remains unknown"))
        var incomplete = finding; incomplete.eventIDs.append("missing-test-evidence")
        XCTAssertEqual(try model.evidence(for: incomplete).missingIDs, ["missing-test-evidence"])
        XCTAssertEqual(try model.evidence(for: incomplete).explanation(for: incomplete), incomplete.whyFlagged)
        model.route = .findings(finding.id)
        model.refresh()
        XCTAssertEqual(model.route, .findings(finding.id), "Refresh must preserve the selected investigation")
    }

    func testReadableMetadataKeepsUnknownValuesAndIdentifiersIntact() {
        XCTAssertEqual(EvidenceValue.display(nil, key: "modifiedAt"), "Not recorded")
        XCTAssertEqual(EvidenceValue.display("UNKNOWN", key: "modifiedAt"), "UNKNOWN")
        XCTAssertEqual(EvidenceValue.display("nan", key: "modifiedAt"), "nan")
        XCTAssertEqual(EvidenceValue.display("abcd1234", key: "sha256"), "abcd1234")
        XCTAssertEqual(EvidenceValue.label("sha256"), "File fingerprint (SHA-256)")
        XCTAssertNotEqual(EvidenceValue.display("1790897401.7", key: "modifiedAt"), "1790897401.7")
    }

    @MainActor func testMetricRecordFiltersMatchStoredCountsAndEventLinks() async throws {
        let store = try EventStore(url: url)
        let initial = Observation(key: "fixture", eventClass: .persistence, component: "SYNTHETIC", attributes: ["value": "original"])
        try store.ingest(CollectorSnapshot(descriptor: descriptor, observations: [initial], complete: true, state: .active, visibility: .limited, detail: "SYNTHETIC"))
        var changed = initial; changed.attributes["value"] = "UNKNOWN test source"
        try store.ingest(CollectorSnapshot(descriptor: descriptor, observations: [changed], complete: true, state: .active, visibility: .limited, detail: "SYNTHETIC"))
        let model = DashboardModel(storeURL: url)
        let view = try XCTUnwrap(model.view)
        XCTAssertEqual(view.events.filter(Investigation.isChange).count, view.changes)
        XCTAssertEqual(view.inventory.filter(Investigation.isUnknown).count, view.unknowns)
        let flagged = try XCTUnwrap(view.events.first { $0.eventType == "CHANGED" })
        XCTAssertEqual(Investigation.findings(for: flagged, in: view.findings).count, 1)
        let baseline = try XCTUnwrap(view.events.first { $0.eventType == "INITIAL" })
        XCTAssertTrue(Investigation.findings(for: baseline, in: view.findings).isEmpty)
    }
}
