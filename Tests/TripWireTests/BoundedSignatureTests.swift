import XCTest
import Foundation
@testable import TripWireCollectors
import TripWireCore

final class BoundedSignatureTests: XCTestCase {
    func testBlockedLookupTimesOutAndCannotEnqueueUnlimitedRetries() {
        let release = DispatchSemaphore(value: 0), entered = DispatchSemaphore(value: 0), finished = expectation(description: "bounded worker returns")
        let pool = BoundedSignatureLookup(limit: 1) { path in
            entered.signal(); release.wait(); finished.fulfill()
            return ProcessIdentity(executablePath: path, signatureStatus: "TEST ONLY")
        }
        let first = pool.identity("/fixture/blocked", timeout: 0.02)
        XCTAssertTrue(first.signatureStatus?.hasPrefix("UNKNOWN") == true)
        XCTAssertEqual(entered.wait(timeout: .now()+1), .success)
        let start = ProcessInfo.processInfo.systemUptime
        for _ in 0..<20 { XCTAssertTrue(pool.identity("/fixture/other", timeout: 1).signatureStatus?.hasPrefix("UNKNOWN") == true) }
        XCTAssertLessThan(ProcessInfo.processInfo.systemUptime-start, 0.5)
        release.signal(); wait(for: [finished], timeout: 2)
    }
    func testCompletedLookupReturnsActualResultAndExhaustedBudgetStaysUnknown() {
        let pool = BoundedSignatureLookup { path in ProcessIdentity(executablePath: path, teamID: "TEST ONLY", signatureStatus: "TEST ONLY") }
        XCTAssertEqual(pool.identity("/fixture", timeout: 1).teamID, "TEST ONLY")
        XCTAssertNil(pool.identity("/fixture", timeout: 0).teamID)
    }
}
