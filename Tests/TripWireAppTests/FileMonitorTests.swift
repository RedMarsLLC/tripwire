import XCTest
import Darwin
import TripWireCore
import TripWireCollectors
@testable import TripWireApp

final class FileMonitorTests: XCTestCase {
    private func storeURL() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("tripwire-managed-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: root) }
        return root.appendingPathComponent("events.sqlite")
    }
    private func channel(_ fixture: String) throws -> (UnsafeMutablePointer<FILE>, Int32) {
        var fds = [Int32](repeating: 0, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
        let file = try XCTUnwrap(fdopen(fds[0], "r+"))
        let bytes = Array(fixture.utf8)
        XCTAssertEqual(write(fds[1], bytes, bytes.count), bytes.count)
        return (file, fds[1])
    }
    func testStatusProtocolDoesNotExposeArbitraryStderr() {
        XCTAssertEqual(FileHelperStatus.parse(Data("TRIPWIRE-HELPER/1 FULL_DISK_ACCESS_REQUIRED".utf8)), .permission)
        XCTAssertNil(FileHelperStatus.parse(Data("TRIPWIRE-HELPER/1 secret document path".utf8)))
        XCTAssertNil(FileHelperStatus.parse(Data("{\"filename\":\"TRIPWIRE-HELPER/1 STARTED\"}".utf8)))
        XCTAssertFalse(FileMonitorPhase.authorizing == .reporting)
    }
    func testDuplicateReceiverIsRejectedBeforeAuthorization() async throws {
        let url = try storeURL()
        let lock = try CollectorOwnerLock(url: url.appendingPathExtension("file-events"))
        let result = await ManagedFileSession.run(bundleURL: URL(fileURLWithPath: "/TEST.app"), storeURL: url, stop: FileMonitorStopToken(), launch: { _ in
            XCTFail("Must not prompt or launch while another receiver owns the store")
            throw TripWireError.message("TEST")
        }, update: { _, _ in })
        withExtendedLifetime(lock) {}
        XCTAssertTrue(result?.contains("Another collector owner") == true)
    }
    func testCancelledStartDoesNotLaunchOrRecordCoverage() async throws {
        let url = try storeURL(), stop = FileMonitorStopToken(); stop.request()
        let result = await ManagedFileSession.run(bundleURL: URL(fileURLWithPath: "/TEST.app"), storeURL: url, stop: stop, launch: { _ in
            XCTFail("Cancelled session must not launch")
            throw TripWireError.message("TEST")
        }, update: { _, _ in XCTFail("Cancelled session must not report") })
        XCTAssertNil(result); XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
    }
    func testPermissionFailureIsSavedAsUnavailableNotReporting() async throws {
        let url = try storeURL()
        let (file, peer) = try channel("TRIPWIRE-HELPER/1 STARTED\nTRIPWIRE-HELPER/1 FULL_DISK_ACCESS_REQUIRED\n")
        defer { close(peer) }
        let result = await ManagedFileSession.run(bundleURL: URL(fileURLWithPath: "/TEST.app"), storeURL: url, stop: FileMonitorStopToken(), launch: { _ in file }, update: { phase, _ in
            XCTAssertNotEqual(phase, .reporting)
        })
        XCTAssertTrue(result?.contains("Full Disk Access") == true)
        let store = try EventStore(url: url)
        let health = try XCTUnwrap(store.sensors().first { $0.id == OpenEventBridge.id })
        XCTAssertEqual(health.state, .error); XCTAssertEqual(health.visibility, .unknown)
        XCTAssertTrue(health.descriptor.source.contains("TripWire-managed"))
        XCTAssertTrue(try store.findings().isEmpty)
        XCTAssertFalse(try store.gaps().isEmpty)
    }
    func testUnexpectedDisconnectRecordsInterruptionAndReleasesOwner() async throws {
        let url = try storeURL()
        let (file, peer) = try channel("TRIPWIRE-HELPER/1 STARTED\n")
        // Half-close the test sender so the app may still send its heartbeat.
        shutdown(peer, SHUT_WR)
        defer { close(peer) }
        let result = await ManagedFileSession.run(bundleURL: URL(fileURLWithPath: "/TEST.app"), storeURL: url, stop: FileMonitorStopToken(), launch: { _ in file }, update: { phase, _ in XCTAssertNotEqual(phase, .reporting) })
        XCTAssertTrue(result?.contains("exited") == true)
        let health = try XCTUnwrap(EventStore(url: url).sensors().first { $0.id == OpenEventBridge.id })
        XCTAssertEqual(health.state, .error)
        XCTAssertNoThrow(try CollectorOwnerLock(url: url.appendingPathExtension("file-events")))
    }
    func testStopClosesPrivatePipeAndRecordsStoppedCoverage() async throws {
        let url = try storeURL(), stop = FileMonitorStopToken()
        let (file, peer) = try channel("")
        defer { close(peer) }
        let result = await ManagedFileSession.run(bundleURL: URL(fileURLWithPath: "/TEST.app"), storeURL: url, stop: stop, launch: { _ in file }, update: { _, _ in stop.request() })
        XCTAssertNil(result)
        var byte: UInt8 = 0
        XCTAssertEqual(read(peer, &byte, 1), 1); XCTAssertEqual(byte, 83, "Explicit stop sent to the helper")
        XCTAssertEqual(read(peer, &byte, 1), 0, "Pipe closes even if the helper does not reply")
        let health = try XCTUnwrap(EventStore(url: url).sensors().first { $0.id == OpenEventBridge.id })
        XCTAssertEqual(health.state, .stopped); XCTAssertEqual(health.visibility, .unknown)
    }
    func testManagedEvidenceKeepsDiagnosticLimitations() {
        XCTAssertTrue(OpenEventBridge.managedLimits.contains { $0.contains("not a native Endpoint Security") })
        XCTAssertTrue(OpenEventBridge.managedLimits.contains { $0.contains("Loss remains unknown") })
        XCTAssertTrue(OpenEventBridge.managedDescriptor.permissions.contains { $0.contains("Full Disk Access") })
    }
}
