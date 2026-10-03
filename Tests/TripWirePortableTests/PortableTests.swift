import XCTest
import Foundation
@testable import TripWireCore
@testable import TripWireCollectors
import TripWireTerminal

final class PortableTests: XCTestCase {
    func testNativeSHA256KeepsEvidenceFingerprintsStable() {
        XCTAssertEqual(Digest.sha256(Data()), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        XCTAssertEqual(Digest.sha256(Data("abc".utf8)), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        XCTAssertEqual(Digest.sha256(Data(repeating: 97, count: 1_000_000)), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
    }
    func testFirstRunReaderDoesNotCreateDiskStateThenCanDiscoverWriter() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("tripwire-portable-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("evidence.sqlite")
        let reader = try EventStore(url: path, access: .readOnly)
        XCTAssertFalse(FileManager.default.fileExists(atPath: directory.path))
        let writer = try EventStore(url: path)
        let descriptor = SensorDescriptor("fixture", "Fixture", source: "TEST ONLY", monitors: "Synthetic test metadata")
        _ = try writer.ingest(CollectorSnapshot(descriptor: descriptor, observations: [], complete: true, state: .active, visibility: .limited, detail: "Fixture"))
        XCTAssertEqual(try reader.readSnapshot { try reader.sensors().count }, 1)
        XCTAssertThrowsError(try reader.setMetadata("test", "write"))
    }
    func testExclusiveCollectorOwnerLockReleases() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("tripwire-lock-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try EventStore(url: directory.appendingPathComponent("evidence.sqlite"))
        var first: CollectorOwnerLock? = try CollectorOwnerLock(url: store.url)
        XCTAssertNotNil(first)
        XCTAssertThrowsError(try CollectorOwnerLock(url: store.url))
        first = nil
        XCTAssertNoThrow(try CollectorOwnerLock(url: store.url))
    }
    func testNativeStoreRefusesHardLinksAndSymlinks() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("tripwire-links-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("evidence.sqlite")
        do { _ = try EventStore(url: path) }
        let link = directory.appendingPathComponent("alias.sqlite")
        try FileManager.default.linkItem(at: path, to: link)
        XCTAssertThrowsError(try EventStore(url: path, access: .readOnly))
        try FileManager.default.removeItem(at: link)
        #if !os(Windows)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: path)
        XCTAssertThrowsError(try EventStore(url: link))
        #endif
    }
    func testPlatformSpecificReviewLocationsAndBoundaries() {
        XCTAssertNotNil(FileAccessReview.reason(path: "/home/test/.config/systemd/user/test.service", home: "/home/test", platform: .linux))
        XCTAssertNotNil(FileAccessReview.reason(path: "/lib/modules/test/extra.ko", home: "/home/test", platform: .linux))
        XCTAssertNil(FileAccessReview.reason(path: "/lib/modules-archive/file", home: "/home/test", platform: .linux))
        XCTAssertNotNil(FileAccessReview.reason(path: #"C:\Users\Test\.SSH\id_ed25519"#, home: #"C:\Users\Test"#, platform: .windows))
        XCTAssertNil(FileAccessReview.reason(path: #"C:\Users\Test\.ssh-backup\key"#, home: #"C:\Users\Test"#, platform: .windows))
    }
    func testNativeResourceSampleIsMeasuredOrUnknownAndMemoryDefinitionIsExplicit() {
        let sample = HostResourceSampler.sample()
        XCTAssertLessThan(abs(sample.timestamp.timeIntervalSinceNow), 5)
        if let memory = sample.ram { XCTAssertGreaterThan(memory.totalBytes, 0); XCTAssertLessThanOrEqual(memory.occupiedBytes, memory.totalBytes); XCTAssertFalse(memory.definition.isEmpty) }
        var metrics = ResourceMetrics(); metrics.ingest(sample)
        XCTAssertNil(metrics.cpu.points.last?.value, "A first counter sample is not a measured interval")
    }
    func testWindowsAccountIdentityPreservesOldEvidence() throws {
        let old = Data(#"{"pid":10,"uid":501,"executablePath":"/fixture"}"#.utf8)
        let decoded = try JSONDecoder().decode(ProcessIdentity.self, from: old)
        XCTAssertEqual(decoded.uid, 501); XCTAssertNil(decoded.accountID)
        let windows = ProcessIdentity(pid: 10, accountID: "S-1-5-21-test", executablePath: #"C:\fixture.exe"#, launchTime: Date(timeIntervalSince1970: 1000))
        XCTAssertNil(windows.uid); XCTAssertNotNil(windows.instanceKey)
        XCTAssertEqual(try JSONDecoder().decode(ProcessIdentity.self, from: JSONEncoder().encode(windows)), windows)
    }
    func testPartialInventoryNeverEstablishesAbsence() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("tripwire-partial-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try EventStore(url: directory.appendingPathComponent("evidence.sqlite"))
        let descriptor = SensorDescriptor("fixture", "Fixture", source: "TEST ONLY", monitors: "Fixture scope")
        let item = Observation(key: "one", eventClass: .listener, component: "test listener", attributes: ["port": "1234"])
        _ = try store.ingest(CollectorSnapshot(descriptor: descriptor, observations: [item], complete: true, absenceReliable: false, state: .degraded, detail: "fixture"))
        let events = try store.ingest(CollectorSnapshot(descriptor: descriptor, observations: [], complete: false, absenceReliable: false, state: .error, detail: "denied"))
        XCTAssertFalse(events.contains { $0.eventType == "REMOVED" })
        XCTAssertTrue(try XCTUnwrap(store.inventory().first).present)
    }
    #if os(Linux)
    func testLinuxSocketParsingAndMalformedSources() {
        let fixture = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345\n"
        let result = LinuxSocket.parse(fixture, tcp: true)
        XCTAssertTrue(result.1); XCTAssertEqual(result.0.first?.localAddress, "127.0.0.1"); XCTAssertEqual(result.0.first?.localPort, 8080)
        XCTAssertEqual(LinuxSocket.endpoint("00000000000000000000000001000000:01BB")?.0, "0:0:0:0:0:0:0:1")
        XCTAssertFalse(LinuxSocket.parse("access denied", tcp: true).1)
        XCTAssertFalse(LinuxSocket.parse(fixture + "malformed\n", tcp: true).1)
        XCTAssertNil(LinuxSocket.endpoint("ZZ:1"))
    }
    func testLinuxProcessStatHandlesSpacesAndParenthesesWithoutArguments() {
        let tail = ["S", "1"] + Array(repeating: "0", count: 9) + ["12", "3"] + Array(repeating: "0", count: 6) + ["500", "1024", "2"]
        let parsed = LinuxProc.statFields("42 (fixture ) name) " + tail.joined(separator: " "))
        XCTAssertEqual(parsed?.pid, 42); XCTAssertEqual(parsed?.parent, 1); XCTAssertEqual(parsed?.started, 500); XCTAssertEqual(parsed?.cpu, 15)
        XCTAssertNil(LinuxProc.statFields("truncated"))
    }
    #endif
}
