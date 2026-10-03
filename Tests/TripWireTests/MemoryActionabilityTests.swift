import XCTest
import TripWireCore

final class MemoryActionabilityTests: XCTestCase {
    func testCacheExcludingEstimateHasDocumentedAccountingAndNoPressureInference() {
        let ram = RAMUsage(totalBytes: 10000, freePages: 1, pageSize: 100, fileBackedPages: 30, compressedPages: 20, wiredPages: 10, anonymousPages: 40, purgeablePages: 5)
        XCTAssertEqual(ram?.occupiedBytes, 9900)
        XCTAssertEqual(ram?.usedEstimateBytes, 6500)
        var metrics = ResourceMetrics()
        metrics.ingest(HostResourceCounters(timestamp: Date(), uptime: 1, cpu: nil, ram: ram))
        XCTAssertEqual(metrics.pressure, .unknown)
        XCTAssertEqual(metrics.pressureHistory.last?.state, .unknown)
        XCTAssertNil(RAMUsage(totalBytes: 100, freePages: 0, pageSize: 100)?.usedEstimateBytes)
        XCTAssertNil(RAMUsage(totalBytes: 100, freePages: 0, pageSize: 100, compressedPages: 1, wiredPages: 1, anonymousPages: 1, purgeablePages: 0)?.usedEstimateBytes)
    }
    func testSwapRateUsesIntervalDeltasNotCumulativeAllocatedSwap() throws {
        let old = SwapCounters(pageIns: 1_000_000, pageOuts: 2_000_000, pageSize: 16384)
        let next = SwapCounters(pageIns: 1_000_128, pageOuts: 2_000_064, pageSize: 16384)
        let rate = try XCTUnwrap(next.rate(since: old, seconds: 2))
        XCTAssertEqual(rate.inMiB, 1)
        XCTAssertEqual(rate.outMiB, 0.5)
        XCTAssertEqual(old.rate(since: old, seconds: 1)?.outMiB, 0)
        XCTAssertNil(next.rate(since: old, seconds: 5))
        XCTAssertNil(old.rate(since: next, seconds: 1))
    }
    func testSwapAndPressureResetAcrossGapAndMissingData() {
        let date = Date(timeIntervalSince1970: 2000)
        var metrics = ResourceMetrics()
        func sample(_ t: Double, swap: SwapCounters?) -> HostResourceCounters { HostResourceCounters(timestamp: date.addingTimeInterval(t), uptime: t, cpu: nil, ram: nil, swap: swap) }
        let swap = SwapCounters(pageIns: 1, pageOuts: 1, pageSize: 4096)
        metrics.ingest(sample(1, swap: swap)); XCTAssertNil(metrics.swapRate)
        metrics.updatePressure(.warning, at: date.addingTimeInterval(1))
        metrics.ingest(sample(2, swap: swap)); XCTAssertEqual(metrics.swapRate?.inMiB, 0)
        XCTAssertEqual(metrics.swapIn.points.last?.value, 0)
        XCTAssertEqual(metrics.swapOut.points.last?.value, 0)
        XCTAssertEqual(metrics.pressureHistory.last?.state, .warning)
        metrics.ingest(sample(8, swap: swap)); XCTAssertNil(metrics.swapRate)
        XCTAssertEqual(metrics.pressureHistory.last?.state, .unknown)
        XCTAssertNil(metrics.swapIn.points.last?.value)
        metrics.ingest(sample(9, swap: nil)); XCTAssertNil(metrics.swapRate)
        metrics.interrupt(at: date.addingTimeInterval(10), reason: "hidden")
        XCTAssertNil(metrics.swapRate)
        XCTAssertNil(metrics.swapOut.points.last?.value)
    }
}
