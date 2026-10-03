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
        let model = DashboardModel(storeURL: store.url)
        let alert = try XCTUnwrap(model.alert)
        XCTAssertEqual(model.tripwireAlerts.count, 1)
        XCTAssertEqual(try model.evidence(for: alert).events.count, 1)
        model.dismissAlert(alert); model.refresh()
        XCTAssertNil(model.alert); XCTAssertEqual(model.tripwireAlerts.count, 1)
        XCTAssertNotNil(try store.event(id: XCTUnwrap(alert.eventIDs.first)))
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
        let overlay = OverlayWindowController()
        try FileManager.default.createDirectory(atPath: output, withIntermediateDirectories: true)
        for (name, route) in [("overview", DashboardRoute.overview), ("tripwires", .tripwires), ("findings", .findings(nil))] {
            model.route = route
            let view = Dashboard().environmentObject(model).environmentObject(overlay).environment(\.colorScheme, .dark).frame(width: 1380, height: 900)
            let host = NSHostingView(rootView: view)
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1380, height: 900), styleMask: [.borderless], backing: .buffered, defer: false)
            window.contentView = host; host.frame = NSRect(x: 0, y: 0, width: 1380, height: 900)
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
