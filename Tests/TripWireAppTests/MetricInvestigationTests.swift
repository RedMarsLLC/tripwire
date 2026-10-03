import XCTest
import TripWireCore
@testable import TripWireApp

final class MetricInvestigationTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 10_000)
    func testClickAndBidirectionalDragSelectFrozenChartTime() {
        let range = MetricSelection.interval(from: 100, to: 200, width: 300, endingAt: now)
        XCTAssertEqual(range.start, now.addingTimeInterval(-40))
        XCTAssertEqual(range.end, now.addingTimeInterval(-20))
        XCTAssertEqual(MetricSelection.interval(from: 200, to: 100, width: 300, endingAt: now), range)
        let click = MetricSelection.interval(from: 150, to: 150, width: 300, endingAt: now)
        XCTAssertEqual(click.start, now.addingTimeInterval(-32))
        XCTAssertEqual(click.end, now.addingTimeInterval(-28))
        XCTAssertEqual(MetricSelection.interval(from: -100, to: 500, width: 300, endingAt: now).duration, 60)
        XCTAssertLessThanOrEqual(MetricSelection.interval(from: 300, to: 300, width: 300, endingAt: now).end, now)
    }
    func testMissingIntervalsNeverSelectDistantValuesOrBridgePause() {
        let points = [MetricPoint(timestamp: now.addingTimeInterval(-50), value: 10),
                      MetricPoint(timestamp: now.addingTimeInterval(-49), value: nil, reason: "Overlay hidden"),
                      MetricPoint(timestamp: now.addingTimeInterval(-10), value: 30)]
        let gap = DateInterval(start: now.addingTimeInterval(-40), end: now.addingTimeInterval(-20))
        XCTAssertTrue(MetricSelection.selected(points, in: gap).isEmpty)
        XCTAssertTrue(MetricSelection.gaps(points, in: gap).contains("Overlay hidden"))
        XCTAssertTrue(MetricSelection.gaps(points, in: gap).contains { $0.contains("unknown") })
        let whole = DateInterval(start: now.addingTimeInterval(-60), end: now)
        XCTAssertTrue(MetricSelection.gaps(points, in: whole).contains { $0.contains("3 seconds") })
    }
    func testFrozenCaptureDoesNotChangeWhenLiveMetricsAdvance() {
        var metrics = ResourceMetrics()
        metrics.ingest(HostResourceCounters(timestamp: now, uptime: 10, cpu: CPUTicks(user: 10, system: 0, idle: 90, nice: 0), ram: nil))
        let capture = MetricCapture(date: now, resources: metrics, apps: AppResourceMetrics(), hooks: AgentActivityView(), hookHistory: AgentActivityHistory())
        let selected = MetricInspection(focus: .hostCPU, interval: DateInterval(start: now.addingTimeInterval(-5), end: now), capture: capture)
        metrics.ingest(HostResourceCounters(timestamp: now.addingTimeInterval(1), uptime: 11, cpu: CPUTicks(user: 110, system: 0, idle: 90, nice: 0), ram: nil))
        XCTAssertEqual(metrics.cpu.points.last?.value, 100)
        XCTAssertEqual(selected.primary.count, 1)
        XCTAssertNil(selected.primary.first?.value)
        XCTAssertEqual(selected.capture.date, now)
        XCTAssertEqual(DashboardRoute.spike.screen, .overview)
    }
    func testTimeWindowQueryFindsHistoricalEvidenceBeyondRecentListAndSignalsTruncation() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try EventStore(url: directory.appendingPathComponent("events.sqlite"))
        let descriptor = SensorDescriptor("fixture", "Fixture", source: "test", monitors: "synthetic")
        func record(_ time: Date, _ value: String) throws {
            try store.ingest(CollectorSnapshot(descriptor: descriptor, timestamp: time,
                observations: [Observation(key: "fixture", eventClass: .persistence, component: "Fixture", attributes: ["value": value])],
                complete: true, state: .active, visibility: .limited, detail: "TEST ONLY"))
        }
        try record(now, "initial")
        try record(now.addingTimeInterval(1), "changed")
        let interval = DateInterval(start: now, end: now.addingTimeInterval(1))
        for index in 0..<205 { try record(now.addingTimeInterval(Double(index + 100)), "later-\(index)") }
        XCTAssertTrue(try store.events().allSatisfy { !interval.contains($0.timestamp) })
        let selected = try store.readSnapshot { try store.evidence(in: interval) }
        XCTAssertEqual(selected.events.count, 2)
        XCTAssertEqual(selected.findings.count, 1)
        XCTAssertFalse(selected.eventsTruncated)
        XCTAssertEqual(selected.findings.first?.eventIDs, selected.events.filter { $0.eventType == "CHANGED" }.map(\.id))
        XCTAssertNotNil(try store.event(id: XCTUnwrap(selected.events.first?.id)))
        let limited = try store.evidence(in: interval, limit: 1)
        XCTAssertEqual(limited.events.count, 1)
        XCTAssertTrue(limited.eventsTruncated)
        XCTAssertFalse(limited.findingsTruncated)
        XCTAssertTrue(try store.evidence(in: DateInterval(start: now.addingTimeInterval(-20), end: now.addingTimeInterval(-10))).events.isEmpty)
    }
}
