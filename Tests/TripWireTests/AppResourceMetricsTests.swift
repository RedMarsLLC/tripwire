import XCTest
import Darwin
import TripWireCore
import TripWireCollectors

final class AppResourceMetricsTests: XCTestCase {
    func testHistoricalAppReadingsRemainBoundedAndSurviveAppExitBriefly() {
        var metrics = AppResourceMetrics()
        metrics.ingest(sample(0, [counter(0)]))
        metrics.ingest(sample(1, [counter(24_000_000)]))
        let captured = metrics
        var empty = sample(2, []); empty.apps = []
        metrics.ingest(empty)
        XCTAssertTrue(metrics.readings.isEmpty)
        XCTAssertEqual(metrics.frames.first { $0.timestamp == origin.addingTimeInterval(1) }?.readings.first?.cpuPercent, 12.5)
        XCTAssertNil(metrics.perApp[app.id]?.points.last?.value)
        for index in 3...100 {
            empty.timestamp = origin.addingTimeInterval(Double(index)); empty.uptime = Double(index + 100)
            metrics.ingest(empty)
        }
        XCTAssertLessThanOrEqual(metrics.frames.count, 64)
        XCTAssertNil(metrics.perApp[app.id])
        XCTAssertEqual(captured.frames.count, 2)
        XCTAssertEqual(captured.frames.last?.readings.first?.cpuPercent, 12.5)
    }
    private let origin = Date(timeIntervalSince1970: 1_000)
    private let app = AIApplication(id: "fixture", name: "Fixture", bundlePath: "/Applications/Fixture.app", pid: 10)
    private func counter(_ ticks: UInt64, pid: Int32 = 10, started: UInt64 = 100) -> AppProcessCounter {
        AppProcessCounter(appID: app.id, pid: pid, started: started, cpuTicks: ticks, footprint: 2048)
    }
    private func sample(_ time: Double, _ processes: [AppProcessCounter], limited: Bool = false, error: String? = nil) -> AppResourceSample {
        AppResourceSample(timestamp: origin.addingTimeInterval(time), uptime: time + 100,
                          secondsPerTick: 1.0 / 24_000_000, coreCount: 8, apps: [app], processes: processes, limited: limited, error: error)
    }
    func testMachTimebaseAndHostShareAndMeasuredZero() throws {
        var metrics = AppResourceMetrics()
        metrics.ingest(sample(0, [counter(100)]))
        XCTAssertNil(metrics.totalCPU)
        XCTAssertEqual(metrics.totalMemory, 2048)
        metrics.ingest(sample(1, [counter(24_000_100)]))
        XCTAssertEqual(try XCTUnwrap(metrics.totalCPU), 12.5, accuracy: 0.001)
        XCTAssertFalse(metrics.limited)
        metrics.ingest(sample(2, [counter(24_000_100)]))
        XCTAssertEqual(metrics.totalCPU, 0)
        XCTAssertEqual(metrics.perApp[app.id]?.points.last?.value, 0)
    }
    func testPIDReuseCounterResetAndImpossibleValuesRemainUnknown() {
        var metrics = AppResourceMetrics()
        metrics.ingest(sample(0, [counter(100)]))
        metrics.ingest(sample(1, [counter(20_000_000, started: 200)]))
        XCTAssertNil(metrics.totalCPU)
        metrics.ingest(sample(2, [counter(1, started: 200)]))
        XCTAssertNil(metrics.totalCPU)
        metrics.ingest(sample(3, [counter(.max, started: 200)]))
        XCTAssertNil(metrics.totalCPU)
        XCTAssertTrue(metrics.limited)
    }
    func testProcessChurnAndMissingSourcesRetainOnlyObservedLowerBound() {
        var metrics = AppResourceMetrics()
        metrics.ingest(sample(0, [counter(0), counter(0, pid: 11)]))
        metrics.ingest(sample(1, [counter(24_000_000), counter(10, pid: 12)]))
        XCTAssertEqual(metrics.totalCPU, 12.5)
        XCTAssertTrue(metrics.limited)
        XCTAssertEqual(metrics.totalMemory, 4096)
        metrics.ingest(sample(2, [], error: "Unavailable"))
        XCTAssertNil(metrics.totalCPU)
        XCTAssertNil(metrics.totalMemory)
        metrics.ingest(sample(3, [counter(48_000_000)]))
        XCTAssertNil(metrics.totalCPU)
    }
    func testEmptyInventoryAndPauseNeverImplyZeroAIUse() {
        var metrics = AppResourceMetrics()
        metrics.ingest(sample(0, []))
        metrics.ingest(sample(1, []))
        XCTAssertNil(metrics.totalCPU)
        XCTAssertNil(metrics.totalMemory)
        metrics.interrupt(at: origin.addingTimeInterval(2))
        XCTAssertFalse(metrics.isFresh(at: origin.addingTimeInterval(2)))
        XCTAssertTrue(metrics.readings.isEmpty)
        metrics.ingest(sample(3, [counter(100)]))
        XCTAssertNil(metrics.totalCPU)
    }
    func testGapAndClockDiscontinuityBreakIntervals() {
        var metrics = AppResourceMetrics()
        metrics.ingest(sample(0, [counter(0)]))
        metrics.ingest(sample(5, [counter(24_000_000)]))
        XCTAssertNil(metrics.totalCPU)
        var changed = sample(6, [counter(48_000_000)])
        changed.uptime += 1
        metrics.ingest(changed)
        XCTAssertNil(metrics.totalCPU)
        XCTAssertFalse(metrics.isFresh(at: origin.addingTimeInterval(10)))
    }
    func testBundleBoundaryAndParentIdentityConstrainProcessGrouping() {
        typealias Process = AIAppResourceSampler.ProcessMetadata
        let processes = [
            Process(pid: 10, parent: 1, started: 10, path: app.bundlePath + "/Contents/MacOS/Fixture"),
            Process(pid: 11, parent: 1, started: 11, path: app.bundlePath + "/Contents/Frameworks/Helper"),
            Process(pid: 12, parent: 10, started: 12, path: "/usr/bin/tool"),
            Process(pid: 13, parent: 12, started: 13, path: "/usr/bin/child"),
            Process(pid: 14, parent: 10, started: 9, path: "/usr/bin/older"),
            Process(pid: 15, parent: 1, started: 15, path: app.bundlePath + "-lookalike/Contents/MacOS/Fixture")
        ]
        let owners = AIAppResourceSampler.owners(apps: [app], processes: processes.reversed())
        XCTAssertEqual(Set(owners.keys), [10, 11, 12, 13])
        XCTAssertTrue(owners.values.allSatisfy { $0 == app.id })
    }
    func testNativeCounterUnitsMatchProcessCPUClock() throws {
        // Real OS counters for this test executable; no synthetic live app data.
        var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        guard proc_pidpath(getpid(), &path, UInt32(path.count)) > 0 else { throw XCTSkip("Own executable path unavailable") }
        let ownApp = AIApplication(id: "test", name: "Test", bundlePath: URL(fileURLWithPath: String(cString: path)).deletingLastPathComponent().path, pid: getpid())
        func cpuClock() -> Double {
            var value = timespec()
            clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &value)
            return Double(value.tv_sec) + Double(value.tv_nsec) / 1_000_000_000
        }
        let before = AIAppResourceSampler.sample(apps: [ownApp]), start = cpuClock()
        while cpuClock() - start < 0.08 { _ = UUID().uuidString }
        let after = AIAppResourceSampler.sample(apps: [ownApp]), elapsed = cpuClock() - start
        guard let first = before.processes.first(where: { $0.pid == getpid() }), let last = after.processes.first(where: { $0.pid == getpid() }) else {
            throw XCTSkip("Own process counters unavailable")
        }
        let measured = Double(last.cpuTicks - first.cpuTicks) * after.secondsPerTick
        XCTAssertEqual(measured, elapsed, accuracy: max(0.03, elapsed * 0.25))
        XCTAssertGreaterThan(last.footprint, 0)
    }
}
