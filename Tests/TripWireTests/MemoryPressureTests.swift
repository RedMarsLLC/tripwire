import XCTest
import Darwin
@testable import TripWireCore
@testable import TripWireCollectors

final class MemoryPressureTests: XCTestCase {
    func testPressureDecodesOnlyVerifiedOSValuesAndExactSize() {
        for (value, expected) in [(UInt32(1), MemoryPressure.normal), (2, .warning), (4, .critical)] {
            XCTAssertEqual(HostResourceSampler.decodePressure(value: value, size: 4, error: 0).state, expected)
        }
        for value: UInt32 in [0, 3, 7, UInt32.max] {
            XCTAssertEqual(HostResourceSampler.decodePressure(value: value, size: 4, error: 0).state, .unknown)
        }
        XCTAssertEqual(HostResourceSampler.decodePressure(value: 1, size: 8, error: 0).state, .unknown)
        let denied = HostResourceSampler.decodePressure(value: 1, size: 4, error: EPERM)
        XCTAssertEqual(denied.state, .unknown); XCTAssertTrue(denied.detail.contains("denied"))
        XCTAssertTrue(HostResourceSampler.decodePressure(value: 1, size: 4, error: ENOENT).detail.contains("does not expose"))
    }
    func testInitialAndPostGapSamplesHavePressureWithoutWaitingForTransition() {
        var metrics = ResourceMetrics()
        let date = Date()
        func sample(_ delta: Double, _ state: MemoryPressure) -> HostResourceCounters {
            HostResourceCounters(timestamp: date.addingTimeInterval(delta), uptime: delta, cpu: nil, ram: nil,
                                 pressure: MemoryPressureReading(state: state, detail: "SYNTHETIC pressure reading"))
        }
        metrics.ingest(sample(0, .warning))
        XCTAssertEqual(metrics.pressure, .warning); XCTAssertEqual(metrics.pressureHistory.last?.state, .warning)
        XCTAssertNil(metrics.cpu.points.last?.value)
        metrics.ingest(sample(20, .normal))
        XCTAssertEqual(metrics.pressure, .normal); XCTAssertNil(metrics.cpu.points.last?.value)
        metrics.ingest(HostResourceCounters(timestamp: date.addingTimeInterval(21), uptime: 21, cpu: nil, ram: nil,
                                           pressure: MemoryPressureReading(state: .unknown, detail: "SYNTHETIC read denied")))
        XCTAssertEqual(metrics.pressure, .unknown); XCTAssertNil(metrics.pressureObservedAt)
        XCTAssertEqual(metrics.pressureDetail, "SYNTHETIC read denied")
        metrics.interrupt(at: date.addingTimeInterval(22), reason: "Sleep")
        XCTAssertTrue(metrics.pressureDetail.contains("Waiting for resource sampling to resume"))
    }
    func testReadOnlyHostPressureHasValueOrSpecificUnavailableReason() {
        let result = HostResourceSampler.memoryPressure()
        XCTAssertFalse(result.detail.isEmpty)
        if result.state == .unknown {
            XCTAssertTrue(result.detail.contains("denied") || result.detail.contains("does not expose") || result.detail.contains("failed") || result.detail.contains("unrecognized"))
        } else { XCTAssertTrue(result.detail.contains("kern.memorystatus_vm_pressure_level")) }
    }
}
