import XCTest
@testable import TripWireCore
@testable import TripWireCollectors

final class ApplicationTests: XCTestCase {
    private var directory: URL!
    private var apps: URL { directory.appendingPathComponent("Applications") }
    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("tripwire-app-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: apps, withIntermediateDirectories: true)
    }
    override func tearDownWithError() throws { try FileManager.default.removeItem(at: directory) }

    @discardableResult private func fixture(_ name: String = "Synthetic.app", version: String = "1") throws -> URL {
        let app = apps.appendingPathComponent(name)
        let contents = app.appendingPathComponent("Contents")
        try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
        let info: [String: Any] = ["CFBundleIdentifier": "test.synthetic", "CFBundleVersion": version, "CFBundleShortVersionString": version, "CFBundleName": "Synthetic test only", "PrivateTestValue": "DO NOT RETAIN THIS CONTENT"]
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: contents.appendingPathComponent("Info.plist"))
        return app
    }

    func testScopedInventoryAllowsOnlyManifestFieldsAndSkipsAppContents() async throws {
        let app = try fixture("Utilities/Synthetic.app")
        try fixture("Utilities/Synthetic.app/Contents/Nested.app")
        try Data("arbitrary file body must not be retained".utf8).write(to: app.appendingPathComponent("Contents/unrelated.txt"))
        let snapshot = await ApplicationCollector(roots: [apps]).collect()
        XCTAssertTrue(snapshot.complete)
        XCTAssertEqual(snapshot.observations.count, 1)
        let observation = try XCTUnwrap(snapshot.observations.first)
        XCTAssertEqual(observation.eventClass, .application)
        XCTAssertEqual(observation.attributes["bundleID"], "test.synthetic")
        XCTAssertEqual(observation.attributes["version"], "1")
        XCTAssertNotNil(observation.attributes["infoPlistSHA256"])
        XCTAssertNil(observation.process, "The subject app is not evidence of the installer/actor")
        let encoded = String(decoding: try JSONEncoder().encode(observation), as: UTF8.self)
        XCTAssertFalse(encoded.contains("DO NOT RETAIN")); XCTAssertFalse(encoded.contains("arbitrary file body"))
    }

    func testAppChangesProduceEvidenceWithoutTrustingInitialInventoryOrInferringAnAgent() async throws {
        let collector = ApplicationCollector(roots: [apps])
        let store = try EventStore(url: directory.appendingPathComponent("evidence.sqlite"))
        try fixture("Existing.app")
        let initial = try store.ingest(await collector.collect())
        XCTAssertEqual(initial.first?.eventType, "INITIAL"); XCTAssertTrue(try store.findings().isEmpty)
        let added = try fixture("Added.app")
        let newEvents = try store.ingest(await collector.collect())
        let new = try XCTUnwrap(newEvents.first)
        XCTAssertEqual(new.eventType, "NEW")
        var finding = try XCTUnwrap(store.findings().first)
        XCTAssertTrue(finding.whyFlagged.contains("intended to install"))
        XCTAssertTrue(finding.whyFlagged.contains("responsible agent")); XCTAssertEqual(finding.intent, "UNKNOWN")
        XCTAssertTrue(finding.limitations.contains { $0.contains("not attribution") })
        try fixture("Added.app", version: "2")
        let changeEvents = try store.ingest(await collector.collect())
        let change = try XCTUnwrap(changeEvents.first)
        XCTAssertEqual(change.previousState?["version"], "1"); XCTAssertEqual(change.currentState?["version"], "2")
        XCTAssertEqual(change.baselineStatus, .new, "A post-baseline app is still new until explicitly approved")
        try FileManager.default.removeItem(at: added)
        let removedEvents = try store.ingest(await collector.collect())
        let removed = try XCTUnwrap(removedEvents.first)
        XCTAssertEqual(removed.eventType, "REMOVED")
        finding = try XCTUnwrap(store.findings().first)
        XCTAssertTrue(Explain.text(finding, events: try store.events()).contains("RESPONSIBLE AGENT\nUNKNOWN"))
    }

    func testMalformedManifestKeepsInventoryPartialAndCannotInventRemoval() async throws {
        let collector = ApplicationCollector(roots: [apps])
        let store = try EventStore(url: directory.appendingPathComponent("evidence.sqlite"))
        let app = try fixture()
        try store.ingest(await collector.collect())
        try FileManager.default.removeItem(at: app)
        let broken = try fixture("Broken.app")
        try Data("invalid manifest".utf8).write(to: broken.appendingPathComponent("Contents/Info.plist"))
        let partial = await collector.collect()
        XCTAssertFalse(partial.complete)
        let events = try store.ingest(partial)
        XCTAssertFalse(events.contains { $0.eventType == "REMOVED" })
        XCTAssertTrue(try XCTUnwrap(store.inventory().first { URL(fileURLWithPath: $0.observation.key).lastPathComponent == app.lastPathComponent }).present)
        let fresh = try EventStore(url: directory.appendingPathComponent("fresh.sqlite"))
        try fresh.ingest(partial)
        XCTAssertNil(try fresh.metadata("baseline:applications"))
        XCTAssertTrue(try fresh.findings().isEmpty)
    }

    func testSymlinkAppAndManifestAreNotFollowed() async throws {
        let target = try fixture("Real.app")
        try FileManager.default.createSymbolicLink(at: apps.appendingPathComponent("Linked.app"), withDestinationURL: target)
        let snapshot = await ApplicationCollector(roots: [apps]).collect()
        let link = try XCTUnwrap(snapshot.observations.first { $0.key.hasSuffix("Linked.app") })
        XCTAssertEqual(link.attributes["bundleID"], "UNKNOWN")
        XCTAssertTrue(link.attributes["bundleMetadata"]?.contains("symlink not followed") == true)
        let info = target.appendingPathComponent("Contents/Info.plist")
        try FileManager.default.moveItem(at: info, to: directory.appendingPathComponent("manifest.plist"))
        try FileManager.default.createSymbolicLink(at: info, withDestinationURL: directory.appendingPathComponent("manifest.plist"))
        let partial = await ApplicationCollector(roots: [apps]).collect()
        XCTAssertFalse(partial.complete)
        let targetObservation = try XCTUnwrap(partial.observations.first { $0.key.hasSuffix("/Real.app") })
        XCTAssertNil(targetObservation.attributes["infoPlistSHA256"])
    }

    func testBoundedOrSymlinkedRootCannotEstablishAbsence() async throws {
        try fixture("One.app"); try fixture("Two.app")
        let bounded = await ApplicationCollector(roots: [apps], entryLimit: 1).collect()
        XCTAssertFalse(bounded.complete); XCTAssertLessThanOrEqual(bounded.observations.count, 1)
        let linked = directory.appendingPathComponent("LinkedRoot")
        try FileManager.default.createSymbolicLink(at: linked, withDestinationURL: apps)
        let snapshot = await ApplicationCollector(roots: [linked]).collect()
        XCTAssertFalse(snapshot.complete); XCTAssertTrue(snapshot.observations.isEmpty)
        let missing = await ApplicationCollector(roots: [directory.appendingPathComponent("OptionalMissing")]).collect()
        XCTAssertTrue(missing.complete)
    }

    func testDepthLimitAndReplacingFolderWithSymlinkCannotInventRemovals() async throws {
        try fixture("Utilities/Nested.app")
        let store = try EventStore(url: directory.appendingPathComponent("evidence.sqlite"))
        try store.ingest(await ApplicationCollector(roots: [apps]).collect())
        let bounded = await ApplicationCollector(roots: [apps], depthLimit: 1).collect()
        XCTAssertFalse(bounded.complete); XCTAssertTrue(bounded.observations.isEmpty)
        let utilities = apps.appendingPathComponent("Utilities")
        let elsewhere = directory.appendingPathComponent("Moved")
        try FileManager.default.moveItem(at: utilities, to: elsewhere)
        try FileManager.default.createSymbolicLink(at: utilities, withDestinationURL: elsewhere)
        let snapshot = await ApplicationCollector(roots: [apps]).collect()
        XCTAssertTrue(snapshot.complete, "Links are outside the explicitly declared plain-folder scope")
        XCTAssertFalse(snapshot.absenceReliable); XCTAssertTrue(snapshot.observations.isEmpty)
        XCTAssertFalse(try store.ingest(snapshot).contains { $0.eventType == "REMOVED" })
        XCTAssertTrue(try XCTUnwrap(store.inventory().first).present)
    }

    func testNonAppDocumentationLinkDoesNotPreventScopedBaselineOrGetRead() async throws {
        try fixture()
        let outside = directory.appendingPathComponent("unreadable-document.html")
        try Data("DO NOT READ THIS DOCUMENT".utf8).write(to: outside)
        try FileManager.default.setAttributes([.posixPermissions: 0], ofItemAtPath: outside.path)
        try FileManager.default.createSymbolicLink(at: apps.appendingPathComponent("Documentation.html"), withDestinationURL: outside)
        let snapshot = await ApplicationCollector(roots: [apps]).collect()
        XCTAssertTrue(snapshot.complete); XCTAssertFalse(snapshot.absenceReliable)
        let store = try EventStore(url: directory.appendingPathComponent("evidence.sqlite"))
        try store.ingest(snapshot)
        XCTAssertNotNil(try store.metadata("baseline:applications"))
        XCTAssertTrue(try store.findings().isEmpty)
        XCTAssertEqual(try store.inventory().count, 1)
        XCTAssertFalse(String(decoding: try JSONEncoder().encode(snapshot.observations), as: UTF8.self).contains("DO NOT READ THIS DOCUMENT"))
    }

    func testKernelAndPortFindingsExplainScopeWithoutAttribution() throws {
        for (collector, cls, expected) in [("kernel-bundles", EventClass.extensions, "loaded into the kernel"), ("extensions", .extensions, "registration"), ("network", .listener, "local address, port")] {
            let observation = Observation(key: "synthetic", eventClass: cls, component: "SYNTHETIC TEST ONLY", attributes: [:])
            let event = EvidenceEvent(timestamp: Date(), sourceCollector: collector, eventType: "NEW", observation: observation, currentState: [:], baselineStatus: .new)
            let finding = try XCTUnwrap(FindingEngine.make(event))
            XCTAssertTrue(finding.whyFlagged.contains(expected))
            XCTAssertTrue(finding.whyFlagged.contains("responsible agent and malicious intent are unknown"))
            if collector == "kernel-bundles" { XCTAssertTrue(finding.title.hasPrefix("Kernel bundle")) }
        }
    }
}
