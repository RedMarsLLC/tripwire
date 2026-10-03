import XCTest
import Darwin
@testable import TripWireCore
@testable import TripWireCollectors

final class FileAccessTests: XCTestCase {
    typealias Sampler = AIFileAccessCollector
    typealias Process = AIAppResourceSampler.ProcessMetadata
    private let app = AIApplication(id: "test.synthetic", name: "Synthetic AI", bundlePath: "/Applications/Synthetic.app", pid: 10)
    private let root = Process(pid: 10, parent: 1, started: 100, path: "/Applications/Synthetic.app/Contents/MacOS/Synthetic")
    private let child = Process(pid: 11, parent: 10, started: 110, path: "/test-only/tool")
    private let path = "/test-home/.ssh/synthetic-key"
    private var file: Sampler.OpenFile { .init(path: path, device: 1, inode: 12, flags: 1) }
    private var directory: URL!
    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("tripwire-file-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }
    override func tearDownWithError() throws { try FileManager.default.removeItem(at: directory) }
    private func sample(partial: Bool = false, values: [Sampler.OpenFile]? = nil) -> CollectorSnapshot {
        let processes = [root, child]
        return Sampler.snapshot(apps: [app], inventory: .init(values: processes, partial: partial),
            metadata: { pid in processes.first { $0.pid == pid } }, files: { _ in .init(values: values ?? [self.file]) }, home: "/test-home")
    }
    func testOpenMetadataCarriesProcessAssociationAndNeverClaimsActualRead() throws {
        let snapshot = sample()
        XCTAssertEqual(snapshot.observations.count, 2)
        let item = try XCTUnwrap(snapshot.observations.first { $0.process?.pid == child.pid })
        XCTAssertEqual(item.attributes["openMode"], "Read-capable")
        XCTAssertEqual(item.attributes["associatedApp"], "Synthetic AI")
        XCTAssertEqual(item.attributes["associationBasis"], "Observed parent chain to recognized app bundle")
        XCTAssertEqual(item.process?.parentPID, 10)
        XCTAssertNil(item.process?.bundleID, "A child executable must not inherit the app's bundle identity")
        XCTAssertNotNil(item.process?.instanceKey)
        XCTAssertTrue(snapshot.complete); XCTAssertFalse(snapshot.absenceReliable)
        XCTAssertEqual(snapshot.visibility, .limited)
        XCTAssertTrue(item.limitations.contains { $0.contains("not proof that bytes were read or written") })
    }
    func testReusedOrReparentedAncestorInvalidatesDescendantAssociation() {
        for replacement in [Process(pid: 10, parent: 1, started: 120, path: root.path), Process(pid: 10, parent: 99, started: 100, path: root.path)] {
            let result = Sampler.snapshot(apps: [app], inventory: .init(values: [root, child], partial: false),
                metadata: { $0 == 10 ? replacement : self.child }, files: { _ in .init(values: [self.file]) }, home: "/test-home")
            XCTAssertTrue(result.observations.isEmpty)
            XCTAssertFalse(result.complete); XCTAssertEqual(result.visibility, .unknown)
        }
    }
    func testPIDReuseForHolderIsRejectedAndUnrelatedProcessIsNeverSampled() {
        let unrelated = Process(pid: 20, parent: 1, started: 5, path: "/Applications/Synthetic.app-copy/fake")
        var sampled: [Int32] = []
        let result = Sampler.snapshot(apps: [app], inventory: .init(values: [root, child, unrelated], partial: false),
            metadata: { pid in pid == 11 ? Process(pid: 11, parent: 10, started: 999, path: self.child.path) : self.root },
            files: { pid in sampled.append(pid); return .init(values: [self.file]) }, home: "/test-home")
        XCTAssertEqual(Set(sampled), [10, 11]); XCTAssertEqual(result.observations.map { $0.process?.pid }, [10])
        XCTAssertFalse(result.complete)
    }
    func testPermissionFailureStaysUnknownButPartialEvidenceIsRetained() {
        let result = Sampler.snapshot(apps: [app], inventory: .init(values: [root], partial: false), metadata: { _ in self.root },
            files: { _ in .init(partial: true, denied: true) }, home: "/test-home")
        XCTAssertEqual(result.state, .error); XCTAssertEqual(result.visibility, .unknown)
        XCTAssertFalse(result.complete); XCTAssertTrue(result.detail.contains("1 process checks reported access denial"))
        let partial = sample(partial: true)
        XCTAssertEqual(partial.observations.count, 2); XCTAssertFalse(partial.complete); XCTAssertEqual(partial.visibility, .limited)
        let failed = Sampler.snapshot(apps: [app], inventory: .init(values: [], partial: true, failed: true), metadata: { _ in nil }, files: { _ in XCTFail("No process inventory"); return .init() })
        XCTAssertEqual(failed.state, .error); XCTAssertEqual(failed.visibility, .unknown)
    }
    func testBoundsDeduplicateDescriptorsAndExposeTruncation() {
        var second = file; second.path += "-second"
        let result = Sampler.snapshot(apps: [app], inventory: .init(values: [root, child], partial: false), metadata: { $0 == 10 ? self.root : self.child },
            files: { _ in .init(values: [self.file, self.file, second]) }, home: "/test-home", maxFiles: 1, maxProcesses: 1)
        XCTAssertEqual(result.observations.count, 1); XCTAssertFalse(result.complete)
        XCTAssertTrue(result.detail.contains("Partial snapshot"))
        XCTAssertEqual(sample(values: [file, file]).observations.count, 2, "One record per process/file/mode, not per duplicate descriptor")
    }
    func testSensitiveLocationsUseExactBoundariesAndDoNotInspectContent() {
        XCTAssertNotNil(FileAccessReview.reason(path: path, home: "/test-home"))
        XCTAssertNil(FileAccessReview.reason(path: "/test-home/.ssh-backup/test", home: "/test-home"))
        XCTAssertNil(FileAccessReview.reason(path: "/other-home/.ssh/test", home: "/test-home"))
        XCTAssertNil(FileAccessReview.reason(path: "/test-home/.ssh/../ordinary", home: "/test-home"))
        XCTAssertNotNil(FileAccessReview.reason(path: "/test-home/.zshrc", home: "/test-home"))
        XCTAssertNil(FileAccessReview.reason(path: "/test-home/.zshrc-copy", home: "/test-home"))
        XCTAssertNotNil(FileAccessReview.reason(path: "/Library/Extensions/Synthetic.kext/code", home: "/test-home"))
    }
    func testInitialAndPartialSensitiveObservationsGenerateFindingsWithoutDuplicateSpamOrAbsence() throws {
        let store = try EventStore(url: directory.appendingPathComponent("events.sqlite"))
        var snapshot = sample(partial: true)
        let first = try store.ingest(snapshot)
        XCTAssertEqual(first.count, 2); XCTAssertEqual(first.first?.baselineStatus, .unknown)
        XCTAssertEqual(try store.findings().count, 2, "Direct sensitive-path evidence does not need a baseline")
        XCTAssertTrue(try store.ingest(snapshot).isEmpty)
        XCTAssertEqual(try store.findings().count, 2)
        snapshot.timestamp = Date().addingTimeInterval(1); snapshot.complete = true
        XCTAssertTrue(try store.ingest(snapshot).isEmpty)
        XCTAssertEqual(try store.latestEvent(collector: Sampler.id, key: first[0].observation.key)?.id, first[0].id)
        // First complete inventory may establish baseline but must not repeat the same review finding.
        XCTAssertEqual(try store.findings().count, 2)
        snapshot.observations = []; snapshot.timestamp = Date().addingTimeInterval(2)
        XCTAssertTrue(try store.ingest(snapshot).isEmpty)
        XCTAssertTrue(try store.inventory().allSatisfy(\.present), "A vanished descriptor never means a deleted file")
        XCTAssertTrue(try store.inventory().allSatisfy { $0.lastSeen < snapshot.timestamp })
        for finding in try store.findings() {
            XCTAssertEqual(finding.intent, "UNKNOWN")
            XCTAssertEqual(finding.ruleID, "ai-sensitive-open-file-v1")
            XCTAssertTrue(finding.whyFlagged.contains("existing access is not automatically trusted"))
            let event = try XCTUnwrap(store.event(id: XCTUnwrap(finding.eventIDs.first)))
            XCTAssertEqual(event.observation.eventClass, .file)
        }
    }
    func testInitialCompleteSnapshotFlagsSensitiveButNotOrdinaryFiles() throws {
        let store = try EventStore(url: directory.appendingPathComponent("events.sqlite"))
        let events = try store.ingest(sample())
        XCTAssertEqual(events.first?.eventType, "INITIAL"); XCTAssertEqual(try store.findings().count, 2)
        var ordinary = file; ordinary.path = "/test-home/project/main.swift"
        let next = try store.ingest(sample(values: [ordinary]))
        XCTAssertEqual(next.count, 2); XCTAssertEqual(try store.findings().count, 2)
        let observed = try XCTUnwrap(next.first)
        XCTAssertEqual(try store.latestEvent(collector: Sampler.id, key: observed.observation.key)?.id, observed.id)
        XCTAssertNil(try store.latestEvent(collector: "different", key: observed.observation.key))
    }
    func testNativeVnodeSamplerReportsModeForSyntheticTestFileWithoutReadingContents() throws {
        let url = directory.appendingPathComponent("synthetic-open-file")
        try Data("TEST CONTENT MUST NOT BE RETAINED".utf8).write(to: url)
        let fd = open(url.path, O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { close(fd) }
        let result = Sampler.openFiles(getpid())
        let resolved = try XCTUnwrap(realpath(url.path, nil))
        defer { free(resolved) }
        let observed = try XCTUnwrap(result.values.first { $0.path == String(cString: resolved) })
        XCTAssertEqual(observed.mode, "Read-capable")
        let writeFD = open(url.path, O_RDWR | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(writeFD, 0); defer { close(writeFD) }
        XCTAssertTrue(Sampler.openFiles(getpid()).values.contains { $0.path == observed.path && $0.mode == "Read/write-capable" })
        let eventFD = open(url.path, O_EVTONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(eventFD, 0); defer { close(eventFD) }
        XCTAssertTrue(Sampler.openFiles(getpid()).values.contains { $0.path == observed.path && $0.mode == "Event-only (no read/write capability)" })
        XCTAssertEqual(lseek(fd, 0, SEEK_CUR), 0, "Sampler must not consume the target file")
    }
    func testCancelingMonitorStopsFileLoopWhileAnotherCollectorIsBlocked() async throws {
        let store = try EventStore(url: directory.appendingPathComponent("events.sqlite"))
        let started = expectation(description: "slow collector started"), resumed = expectation(description: "slow collector returned")
        let fileStarted = expectation(description: "file loop started")
        let slow = PausedFileCollector(snapshot: CollectorSnapshot(descriptor: SensorDescriptor("test-slow", "Synthetic slow source", source: "Test", monitors: "Test only"), complete: true, detail: "Test only"), started: started, resumed: resumed,
            descriptor: SensorDescriptor("test-slow", "Synthetic slow source", source: "Test", monitors: "Test only"))
        let files = CountingFileCollector(started: fileStarted)
        let monitor = Monitor(store: store, collectors: [slow, files])
        let task = Task { try await monitor.sample(continuousFiles: true) }
        await fulfillment(of: [started, fileStarted], timeout: 2)
        task.cancel()
        let before = await files.count
        try await Task.sleep(nanoseconds: 2_100_000_000)
        let after = await files.count
        XCTAssertEqual(after, before, "Cancel must stop file polling before a slow sibling returns")
        await slow.resume()
        try await task.value
        await fulfillment(of: [resumed], timeout: 2)
        try monitor.stop()
    }
    func testStoppingSessionRejectsAnInFlightSnapshot() async throws {
        let store = try EventStore(url: directory.appendingPathComponent("events.sqlite"))
        let started = expectation(description: "collector started"), resumed = expectation(description: "collector returned")
        let gate = PausedFileCollector(snapshot: sample(), started: started, resumed: resumed)
        let session = FileWatchSession(store: store, collector: gate, interval: 1_000_000)
        await fulfillment(of: [started], timeout: 2)
        session.stop()
        await gate.resume()
        await fulfillment(of: [resumed], timeout: 2)
        // Let the canceled task reach its commit guard after the collector returns.
        try await Task.sleep(nanoseconds: 30_000_000)
        XCTAssertTrue(try store.inventory().isEmpty); XCTAssertTrue(try store.sensors().isEmpty)
    }
}

private actor PausedFileCollector: Collector {
    nonisolated let descriptor: SensorDescriptor
    let snapshot: CollectorSnapshot
    let started: XCTestExpectation, resumed: XCTestExpectation
    private var continuation: CheckedContinuation<Void, Never>?
    init(snapshot: CollectorSnapshot, started: XCTestExpectation, resumed: XCTestExpectation, descriptor: SensorDescriptor = AIFileAccessCollector().descriptor) {
        self.descriptor = descriptor
        self.snapshot = snapshot; self.started = started; self.resumed = resumed
    }
    func collect() async -> CollectorSnapshot {
        await withCheckedContinuation { continuation in self.continuation = continuation; started.fulfill() }
        resumed.fulfill(); return snapshot
    }
    func resume() { continuation?.resume(); continuation = nil }
}

private actor CountingFileCollector: Collector {
    nonisolated let descriptor = AIFileAccessCollector().descriptor
    let started: XCTestExpectation
    var count = 0
    init(started: XCTestExpectation) { self.started = started }
    func collect() async -> CollectorSnapshot {
        count += 1
        if count == 1 { started.fulfill() }
        return CollectorSnapshot(descriptor: descriptor, complete: true, absenceReliable: false, detail: "Synthetic test-only empty snapshot")
    }
}
