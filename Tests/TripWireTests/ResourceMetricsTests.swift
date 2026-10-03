import XCTest
@testable import TripWireCore
import TripWireCollectors

final class ResourceMetricsTests: XCTestCase {
    private let origin = Date(timeIntervalSince1970: 1000)
    private func counters(_ t: Double, cpu: CPUTicks? = CPUTicks(user: 10, system: 10, idle: 80, nice: 0), ram: RAMUsage? = RAMUsage(totalBytes: 1000, freePages: 2, pageSize: 100)) -> HostResourceCounters {
        HostResourceCounters(timestamp: origin.addingTimeInterval(t), uptime: t + 100, cpu: cpu, ram: ram)
    }
    func testCPUNormalizesWholeHostAndPreservesRealZero() throws {
        let old = CPUTicks(user: 100, system: 100, idle: 100, nice: 100)
        let busy = CPUTicks(user: 120, system: 110, idle: 160, nice: 110)
        XCTAssertEqual(try XCTUnwrap(busy.utilization(since: old)), 40, accuracy: 0.001)
        XCTAssertEqual(CPUTicks(user: 100, system: 100, idle: 200, nice: 100).utilization(since: old), 0)
        XCTAssertNil(old.utilization(since: old))
        XCTAssertNil(old.utilization(since: busy))
    }
    func testRAMDefinitionIncludesEverythingExceptFreePagesAndRejectsInvalidCounters() {
        let ram = RAMUsage(totalBytes: 16_384, freePages: 1, pageSize: 4096)
        XCTAssertEqual(ram?.occupiedBytes, 12_288)
        XCTAssertEqual(ram?.percent, 75)
        XCTAssertEqual(RAMUsage(totalBytes: 100, freePages: 1, pageSize: 100)?.percent, 0)
        XCTAssertNil(RAMUsage(totalBytes: 0, freePages: 0, pageSize: 4096))
        XCTAssertNil(RAMUsage(totalBytes: 10, freePages: 100, pageSize: 4096))
        XCTAssertNil(RAMUsage(totalBytes: 100, freePages: .max, pageSize: .max))
    }
    func testMissingSourcesAreIndependentAndNeverBecomeZero() {
        var metrics = ResourceMetrics()
        metrics.ingest(counters(0))
        XCTAssertNil(metrics.cpu.points.last?.value)
        XCTAssertEqual(metrics.latestRAM?.percent, 80)
        metrics.ingest(counters(1, cpu: nil))
        XCTAssertNil(metrics.cpu.points.last?.value)
        XCTAssertNotNil(metrics.latestRAM)
        metrics.ingest(counters(2, ram: nil))
        XCTAssertNil(metrics.ram.points.last?.value)
        XCTAssertNil(metrics.latestRAM)
        XCTAssertNil(metrics.cpu.points.last?.value)
        metrics.ingest(counters(3, cpu: CPUTicks(user: 20, system: 20, idle: 160, nice: 0)))
        XCTAssertEqual(metrics.cpu.points.last?.value, 20)
    }
    func testSamplingGapAndSleepResetCPUAndPressure() {
        var metrics = ResourceMetrics()
        metrics.ingest(counters(0))
        XCTAssertEqual(metrics.pressure, .unknown)
        metrics.updatePressure(.warning, at: origin)
        XCTAssertFalse(metrics.ingest(counters(5)))
        XCTAssertNil(metrics.cpu.points.last?.value)
        XCTAssertEqual(metrics.pressure, .unknown)
        metrics.updatePressure(.normal, at: origin.addingTimeInterval(5))
        metrics.interrupt(at: origin.addingTimeInterval(6), reason: "sleep")
        XCTAssertNil(metrics.lastSample)
        XCTAssertNil(metrics.latestRAM)
        XCTAssertNil(metrics.cpu.points.last?.value)
        XCTAssertEqual(metrics.pressure, .unknown)
        metrics.ingest(counters(30))
        XCTAssertNil(metrics.cpu.points.last?.value)
    }
    func testStalenessAndClockChangeAreUnknown() {
        var metrics = ResourceMetrics()
        metrics.ingest(counters(0))
        XCTAssertTrue(metrics.isFresh(at: origin.addingTimeInterval(2)))
        XCTAssertFalse(metrics.isFresh(at: origin.addingTimeInterval(4)))
        XCTAssertFalse(metrics.isFresh(at: origin.addingTimeInterval(-1)))
        var changed = counters(1); changed.uptime = 99
        XCTAssertFalse(metrics.ingest(changed))
        XCTAssertNil(metrics.cpu.points.last?.value)
    }
    func testHistoryIsTimeAndCountBoundedAndRejectsNonfiniteValues() {
        var history = MetricHistory()
        for index in 0...10_000 {
            history.append(MetricPoint(timestamp: origin.addingTimeInterval(Double(index) / 100), value: 10))
        }
        XCTAssertLessThanOrEqual(history.points.count, 64)
        history.append(MetricPoint(timestamp: origin.addingTimeInterval(200), value: .nan))
        XCTAssertEqual(history.points.count, 1)
        XCTAssertNil(history.points.first?.value)
        history.append(MetricPoint(timestamp: origin, value: 0))
        XCTAssertEqual(history.points.count, 1)
        XCTAssertEqual(history.points.first?.value, 0)
    }
    func testAgentAttributionRequiresIdentityAndEvidenceAndDoesNotInferZero() throws {
        XCTAssertNil(AttributedAgentActivity(evidenceID: "", timestamp: origin, kind: .file, agentID: "agent", processInstanceKey: "instance", attributionSource: "adapter"))
        XCTAssertNil(AttributedAgentActivity(evidenceID: "event", timestamp: origin, kind: .process, agentID: " ", processInstanceKey: "instance", attributionSource: "adapter"))
        XCTAssertNil(AgentActivityReading.unavailable.eventsPerMinute)
        let incomplete = AgentActivityReading.evaluate(events: [], coverageStart: origin.addingTimeInterval(-5), coverageEnd: origin, now: origin)
        XCTAssertNil(incomplete.eventsPerMinute)
        let complete = AgentActivityReading.evaluate(events: [], coverageStart: origin.addingTimeInterval(-60), coverageEnd: origin, now: origin)
        XCTAssertEqual(complete.eventsPerMinute, 0)
        XCTAssertNil(AgentActivityReading.evaluate(events: [], coverageStart: origin.addingTimeInterval(-60), coverageEnd: origin.addingTimeInterval(-1), now: origin).eventsPerMinute)
    }
    func testAttributedMinuteDeduplicatesEvidenceAndKeepsMarkerCategories() throws {
        let events = try AgentActivityKind.allCases.enumerated().map { index, kind in
            try XCTUnwrap(AttributedAgentActivity(evidenceID: "event-\(index)", timestamp: origin.addingTimeInterval(-Double(index)), kind: kind,
                                                  agentID: "test-agent", processInstanceKey: "123:launch:path", attributionSource: "test-only verified adapter"))
        }
        let old = try XCTUnwrap(AttributedAgentActivity(evidenceID: "old", timestamp: origin.addingTimeInterval(-61), kind: .file, agentID: "test", processInstanceKey: "key", attributionSource: "fixture"))
        let result = AgentActivityReading.evaluate(events: events + events + [old], coverageStart: origin.addingTimeInterval(-60), coverageEnd: origin, now: origin)
        XCTAssertEqual(result.eventsPerMinute, AgentActivityKind.allCases.count)
        XCTAssertEqual(Set(result.markers.map(\.kind)), Set(AgentActivityKind.allCases))
    }
    func testRealMachSamplerReturnsValidBoundedValuesOrExplicitMissingData() throws {
        // Live read-only smoke check. Never substitute fixtures if OS rejects it.
        let result = HostResourceSampler.sample()
        XCTAssertLessThan(abs(result.timestamp.timeIntervalSinceNow), 3)
        XCTAssertGreaterThan(result.uptime, 0)
        if let ram = result.ram {
            XCTAssertTrue((0...100).contains(ram.percent))
            XCTAssertEqual(ram.totalBytes, ProcessInfo.processInfo.physicalMemory)
        }
    }
}
