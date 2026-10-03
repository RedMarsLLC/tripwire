import XCTest
import TripWireCore
import TripWireCollectors
@testable import TripWireApp

final class CheckSummaryTests: XCTestCase {
    private func sensors() -> [SensorHealth] {
        CollectorRegistry.make(storeURL: URL(fileURLWithPath: "/test-only/unused.sqlite")).map { SensorHealth(descriptor: $0.descriptor) }
    }
    func testCheckCatalogExcludesUnimplementedAndUnconfiguredCanary() {
        let summary = CheckSummary(sensors: sensors(), running: false, sampling: false, readError: nil)
        XCTAssertEqual(Set(summary.available.map(\.id)), ["ai-open-files", "applications", "processes", "network", "persistence", "extensions", "kernel-bundles", "hardware", "configuration", "watchdog-integrity"])
        XCTAssertEqual(summary.notImplemented.count, 6); XCTAssertEqual(summary.optional.map(\.id), ["canaries"])
        XCTAssertEqual(summary.value, "PAUSED"); XCTAssertTrue(summary.paused)
        XCTAssertEqual(summary.focus, .all)
        XCTAssertTrue(summary.explanation.contains("CPU/RAM charts run separately"))
        XCTAssertTrue(summary.catalogExplanation.contains("collector registry"))
    }
    func testFreshReportsDoNotHideFailedOrStaleChecks() {
        var rows = sensors()
        for index in rows.indices {
            rows[index].state = .degraded; rows[index].visibility = .limited
            rows[index].initialized = true; rows[index].lastHeartbeat = Date(); rows[index].lastSuccess = Date()
        }
        let network = rows.firstIndex { $0.id == "network" }!
        rows[network].state = .error; rows[network].detail = "SYNTHETIC source failure"
        let stale = rows.firstIndex { $0.id == "processes" }!
        rows[stale].lastHeartbeat = Date().addingTimeInterval(-120)
        let summary = CheckSummary(sensors: rows, running: true, sampling: true, readError: nil)
        XCTAssertEqual(summary.failed.map(\.id), ["network"])
        XCTAssertEqual(summary.waiting.map(\.id), ["processes"])
        XCTAssertFalse(summary.reporting.contains { $0.id == "endpoint-security" })
        XCTAssertEqual(summary.focus, .attention)
        XCTAssertTrue(summary.headline.contains("1 CHECK NEEDS ATTENTION"))
        XCTAssertTrue(summary.explanation.contains("SYNTHETIC source failure"))
        XCTAssertEqual(summary.available.count, 11, "An explicitly configured canary participates in check counts")
    }
    func testStoreFailureDoesNotLookLikePausedOrZeroHealthyChecks() {
        let summary = CheckSummary(sensors: sensors(), running: false, sampling: false, readError: "test read failure")
        XCTAssertFalse(summary.paused); XCTAssertEqual(summary.value, "UNREADABLE")
        XCTAssertTrue(summary.explanation.contains("Counts are unavailable"))
        XCTAssertEqual(summary.focus, .all)
    }
    func testFailedCanaryIsNotMisclassifiedAsOptionalConfiguration() {
        var rows = sensors()
        let index = rows.firstIndex { $0.id == "canaries" }!
        rows[index].state = .error; rows[index].visibility = .unknown
        let summary = CheckSummary(sensors: rows, running: true, sampling: true, readError: nil)
        XCTAssertTrue(summary.optional.isEmpty)
        XCTAssertEqual(summary.failed.map(\.id), ["canaries"])
        XCTAssertEqual(SensorPresentation(rows[index]).kind, .attention)
    }
    func testFileWatchStalenessDoesNotPresentLiveFileCoverage() {
        var rows = sensors()
        for index in rows.indices where rows[index].id != "canaries" {
            rows[index].state = .degraded; rows[index].visibility = .limited; rows[index].lastHeartbeat = Date()
        }
        let file = rows.firstIndex { $0.id == "ai-open-files" }!
        rows[file].lastHeartbeat = Date().addingTimeInterval(-11)
        let summary = CheckSummary(sensors: rows, running: true, sampling: true, readError: nil)
        XCTAssertEqual(summary.waiting.map(\.id), ["ai-open-files"])
        XCTAssertFalse(summary.headline.contains("FILE WATCH: SNAPSHOTS"))
        XCTAssertEqual(summary.destination, .coverage(.attention))
    }
    func testFileSnapshotsLinkToEvidenceAndDiscloseMissingFullAudit() {
        var rows = sensors()
        for index in rows.indices where rows[index].id != "canaries" {
            rows[index].state = .active; rows[index].visibility = .limited; rows[index].lastHeartbeat = Date()
        }
        let summary = CheckSummary(sensors: rows, running: true, sampling: true, readError: nil)
        XCTAssertEqual(summary.value, "10 LIVE")
        XCTAssertEqual(summary.headline, "FILE WATCH: SNAPSHOTS ↗")
        XCTAssertEqual(summary.focus, .sensor("ai-open-files"))
        XCTAssertEqual(summary.destination, .files)
        XCTAssertTrue(summary.explanation.contains("actual reads/writes are not audited"))
    }
}
