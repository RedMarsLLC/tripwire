import XCTest
import SwiftUI
import AppKit
import TripWireCore
@testable import TripWireApp

final class TripwiresDashboardTests: XCTestCase {
    @MainActor func testAlertDismissalRetainsFindingAndEvidence() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("tripwire-alert-test-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try EventStore(url: root.appendingPathComponent("events.sqlite"))
        try store.saveTripwire(TripwireRule(name: "Fixture boundary", path: "/fixture/private", kind: .folder))
        let observation = Observation(key: "test-handle", eventClass: .file, component: "/fixture/private/file", attributes: ["path": "/fixture/private/file", "associatedApp": "TEST ONLY", "associationBasis": "Synthetic test association"])
        try store.ingest(CollectorSnapshot(descriptor: SensorDescriptor("ai-open-files", "Fixture", source: "TEST ONLY", monitors: "Synthetic test data"), observations: [observation], state: .degraded, visibility: .limited, detail: "Fixture"))
        var second = observation; second.key = "second-handle"; second.component += "-second"; second.attributes["path"] = second.component
        try store.ingest(CollectorSnapshot(descriptor: SensorDescriptor("ai-open-files", "Fixture", source: "TEST ONLY", monitors: "Synthetic test data"), observations: [second], state: .degraded, visibility: .limited, detail: "Fixture"))
        let model = DashboardModel(storeURL: store.url)
        let alert = try XCTUnwrap(model.alert)
        XCTAssertEqual(model.tripwireAlerts.count, 2)
        XCTAssertEqual(try model.evidence(for: alert).events.count, 1)
        model.dismissAlert(alert); model.refresh()
        XCTAssertNil(model.alert); XCTAssertEqual(model.tripwireAlerts.count, 2)
        XCTAssertNotNil(try store.event(id: XCTUnwrap(alert.eventIDs.first)))
        var fresh = observation; fresh.key = "new-handle"; fresh.component += "-new"; fresh.attributes["path"] = fresh.component
        try store.ingest(CollectorSnapshot(descriptor: SensorDescriptor("ai-open-files", "Fixture", source: "TEST ONLY", monitors: "Synthetic test data"), observations: [fresh], state: .degraded, visibility: .limited, detail: "Fixture"))
        model.refresh(); XCTAssertEqual(model.alert?.component, fresh.component)
        XCTAssertEqual(model.tripwireAlerts.count, 3)
    }
    @MainActor func testClearingQueueRefreshesCountsAndBannerAndKeepsEvidence() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("tripwire-clear-dashboard-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try EventStore(url: root.appendingPathComponent("events.sqlite"))
        try store.saveTripwire(TripwireRule(name: "TEST ONLY", path: "/fixture/private", kind: .folder))
        let observation = Observation(key: "test-handle", eventClass: .file, component: "/fixture/private/file", attributes: ["path": "/fixture/private/file", "associatedApp": "TEST ONLY", "associationBasis": "Synthetic test association"], confidence: .moderate)
        try store.ingest(CollectorSnapshot(descriptor: SensorDescriptor("ai-open-files", "Fixture", source: "TEST ONLY", monitors: "Synthetic test data"), observations: [observation], state: .degraded, visibility: .limited, detail: "Fixture"))
        let model = DashboardModel(storeURL: store.url)
        let finding = try XCTUnwrap(model.alert)
        let targets = model.openFindings.map { FindingReviewTarget(findingID: $0.id, expectedReviewID: model.view?.assessment(for: $0).latestReview?.id) }
        let count = try await model.clearQueue(targets)
        XCTAssertEqual(count, 1); XCTAssertTrue(model.openFindings.isEmpty); XCTAssertNil(model.alert)
        XCTAssertEqual(model.view?.assessment(for: finding).status, .cleared)
        XCTAssertEqual(try model.evidence(for: finding).events.count, 1)
        XCTAssertTrue(model.view?.tripwires.first?.enabled == true)
    }
    func testDismissedBurstStaysClearAndRearmsAfterQuiet() throws {
        let data: [String: Any] = ["id": "TEST-1", "timestamp": 0, "title": "TEST ONLY", "whatHappened": "Process 10 opened a test file", "whyFlagged": "TEST ONLY", "component": "/fixture/file", "eventIDs": [], "baselineDifference": "TEST rule revision 1", "confidence": "MODERATE", "severity": "ELEVATED", "limitations": ["TEST ONLY"], "suggestedInvestigation": [], "intent": "UNKNOWN", "ruleID": "user-tripwire:TEST"]
        let first = try JSONDecoder.stored.decode(Finding.self, from: JSONSerialization.data(withJSONObject: data))
        var state = AlertBannerState()
        XCTAssertEqual(state.next([first], now: 0)?.id, first.id)
        state.dismiss([first], now: 1)
        XCTAssertNil(state.next([first], now: 2))
        var repeatEvent = first; repeatEvent.id = "TEST-2"
        XCTAssertNil(state.next([repeatEvent, first], now: 20))
        var laterRepeat = first; laterRepeat.id = "TEST-3"
        XCTAssertNil(state.next([laterRepeat, repeatEvent, first], now: 40), "Continuing identical activity stays quiet")
        var newAction = first; newAction.id = "TEST-4"; newAction.whatHappened = "Process 10 wrote the test file"
        XCTAssertEqual(state.next([newAction, laterRepeat], now: 41)?.id, newAction.id)
        var resumed = first; resumed.id = "TEST-5"
        XCTAssertEqual(state.next([resumed, laterRepeat], now: 71)?.id, resumed.id, "After a quiet period a new occurrence alerts again")
        XCTAssertNil(state.next([laterRepeat, repeatEvent, first], now: 100), "Old dismissed evidence never becomes a new banner")
        var changedRule = first; changedRule.id = "TEST-6"; changedRule.baselineDifference = "TEST rule revision 2"
        state.dismiss([first], now: 100)
        XCTAssertEqual(state.next([changedRule, first], now: 101)?.id, changedRule.id)
    }
    @MainActor func testConfigurationRoundTripAndNavigation() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("tripwire-dashboard-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let model = DashboardModel(storeURL: root.appendingPathComponent("events.sqlite"))
        let rule = TripwireRule(name: "Test boundary", path: root.appendingPathComponent("never-opened").path, kind: .folder)
        XCTAssertTrue(model.saveTripwire(rule)); XCTAssertEqual(model.view?.tripwires.count, 1)
        XCTAssertNil(model.configurationError)
        XCTAssertEqual(DashboardRoute.page(.tripwires), .tripwires)
        XCTAssertEqual(DashboardRoute.tripwires.screen, .tripwires)
        model.deleteTripwire(rule); XCTAssertTrue(model.view?.tripwires.isEmpty == true)
    }
    /// Render this app's own empty-store views without capturing the user's screen.
    @MainActor func testOptionalDashboardRender() throws {
        guard let output = ProcessInfo.processInfo.environment["TRIPWIRE_RENDER_DIR"] else { return }
        _ = NSApplication.shared
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("tripwire-render-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let model = DashboardModel(storeURL: root.appendingPathComponent("events.sqlite"))
        // Synthetic records live only in this test target and its temporary store.
        let writer = try EventStore(url: model.storeURL)
        try writer.saveTripwire(TripwireRule(name: "Fixture boundary", path: "/fixture/private", kind: .folder))
        for index in 0..<5 {
            let path = "/fixture/private/test-\(index)"
            let row = Observation(key: "test-\(index)", eventClass: .file, component: path, attributes: ["path": path, "associatedApp": "TEST AI", "associationBasis": "Synthetic test association"], confidence: .moderate)
            try writer.ingest(CollectorSnapshot(descriptor: SensorDescriptor("ai-open-files", "TEST ONLY", source: "TEST ONLY", monitors: "Fixture"), observations: [row], complete: false, absenceReliable: false, state: .degraded, visibility: .limited, detail: "TEST ONLY"))
            let finding = try XCTUnwrap(writer.findings().first { $0.component == path })
            let level = RiskLevel.allCases[index]
            if level != .high { try writer.reviewFinding(id: finding.id, level: level, status: .open, reason: "TEST ONLY: demonstrate a local correction", expectedReviewID: nil) }
        }
        model.refresh()
        let overlay = OverlayWindowController()
        try FileManager.default.createDirectory(atPath: output, withIntermediateDirectories: true)
        for (name, route, width) in [("overview", DashboardRoute.overview, 1380.0), ("overview-compact", .overview, 950.0), ("tripwires", .tripwires, 1380.0), ("findings", .findings(nil), 1380.0)] {
            model.route = route
            let view = Dashboard().environmentObject(model).environmentObject(overlay).environment(\.colorScheme, .dark).frame(width: width, height: 900)
            let host = NSHostingView(rootView: view)
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: width, height: 900), styleMask: [.borderless], backing: .buffered, defer: false)
            window.contentView = host; host.frame = NSRect(x: 0, y: 0, width: width, height: 900)
            host.layoutSubtreeIfNeeded()
            RunLoop.main.run(until: Date().addingTimeInterval(0.15))
            host.layoutSubtreeIfNeeded(); host.displayIfNeeded()
            let bitmap = try XCTUnwrap(host.bitmapImageRepForCachingDisplay(in: host.bounds))
            host.cacheDisplay(in: host.bounds, to: bitmap)
            let data = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))
            try data.write(to: URL(fileURLWithPath: output).appendingPathComponent("dashboard-\(name).png"))
        }
    }
}
