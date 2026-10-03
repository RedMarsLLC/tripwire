import XCTest
import CSQLite
@testable import TripWireCore
@testable import TripWireCollectors
@testable import TripWireTerminal

final class CoreTests: XCTestCase {
    var directory: URL!
    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("tripwire-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }
    override func tearDownWithError() throws { if let directory { try FileManager.default.removeItem(at: directory) } }
    func store() throws -> EventStore { try EventStore(url: directory.appendingPathComponent("events.sqlite")) }
    let descriptor = SensorDescriptor("fixture", "Fixture", source: "SYNTHETIC TEST ONLY", monitors: "Tests")
    func observation(_ key: String = "agent", _ value: String = "/Applications/Example.app/helper") -> Observation {
        Observation(key: key, eventClass: .persistence, component: "SYNTHETIC \(key)", attributes: ["executable": value, "ownerUID": "501"])
    }
    func sample(_ observations: [Observation], complete: Bool = true, state: SensorState = .active, date: Date = Date()) -> CollectorSnapshot {
        CollectorSnapshot(descriptor: descriptor, timestamp: date, observations: observations, complete: complete, state: state, visibility: .available, detail: "SYNTHETIC TEST")
    }
    func testInitialInventoryEstablishesObservationBaselineWithoutFindings() throws {
        let s = try store(); let events = try s.ingest(sample([observation()]))
        XCTAssertEqual(events.first?.eventType, "INITIAL"); XCTAssertEqual(events.first?.baselineStatus, .known)
        XCTAssertTrue(try s.findings().isEmpty)
        XCTAssertEqual(try s.inventory().first?.baselineAttributes?["executable"], "/Applications/Example.app/helper")
    }
    func testUnknownIncompleteFirstScanNeverEstablishesBaseline() throws {
        let s = try store(); let events = try s.ingest(sample([observation()], complete: false))
        XCTAssertEqual(events.first?.baselineStatus, .unknown); XCTAssertNil(try s.metadata("baseline:fixture")); XCTAssertTrue(try s.findings().isEmpty)
    }
    func testPartialInventoryCannotInventRemovals() throws {
        let s = try store(); try s.ingest(sample([observation()]))
        XCTAssertTrue(try s.ingest(sample([], complete: false, state: .error)).isEmpty)
        XCTAssertEqual(try s.inventory().first?.present, true)
        XCTAssertFalse(try s.gaps().isEmpty)
    }
    func testCompleteInventoryDetectsRemovalAndPreservesOldEvidence() throws {
        let s = try store(); try s.ingest(sample([observation()]))
        let removal = try s.ingest(sample([])).first!
        XCTAssertEqual(removal.eventType, "REMOVED"); XCTAssertNil(removal.currentState); XCTAssertNotNil(removal.previousState)
        XCTAssertEqual(try s.findings().count, 1); XCTAssertEqual(try s.inventory().first?.present, false)
    }
    func testChangePersistsUntilExplicitApprovalAndBaselineNeverDrifts() throws {
        let s = try store(); try s.ingest(sample([observation()]))
        let changed = observation("agent", "/tmp/fixture-helper")
        try s.ingest(sample([changed])); try s.ingest(sample([changed]))
        var record = try XCTUnwrap(s.inventory().first)
        XCTAssertEqual(record.baselineStatus, .changed); XCTAssertEqual(record.baselineAttributes?["executable"], "/Applications/Example.app/helper")
        try s.approve(key: record.id, expectedFingerprint: record.observation.fingerprint); try s.ingest(sample([changed])); record = try XCTUnwrap(s.inventory().first)
        XCTAssertEqual(record.baselineStatus, .userApproved)
        try s.ingest(sample([observation("agent", "/tmp/another-fixture")]))
        XCTAssertEqual(try s.inventory().first?.baselineStatus, .changed)
        XCTAssertEqual(try s.events().filter { $0.eventType == "APPROVAL" }.count, 1)
    }
    func testNewDoesNotBecomeTrustedWithAge() throws {
        let s = try store(); try s.ingest(sample([])); try s.ingest(sample([observation()]))
        try s.ingest(sample([observation()], date: Date().addingTimeInterval(1_000_000)))
        XCTAssertEqual(try s.inventory().first?.baselineStatus, .new)
    }
    func testFingerprintAndDiffAreDeterministic() {
        let a = Observation(key: "a", eventClass: .configuration, component: "fixture", attributes: ["x": "1", "y": "2"])
        let b = Observation(key: "a", eventClass: .configuration, component: "fixture", attributes: ["y": "2", "x": "1"])
        XCTAssertEqual(a.fingerprint, b.fingerprint)
        XCTAssertEqual(BaselineEngine.differences(["a": "ON"], ["a": "OFF"]), ["a: ON -> OFF"])
    }
    func testFindingHasExplanationEvidenceAndUnknownIntent() throws {
        let s = try store(); try s.ingest(sample([])); try s.ingest(sample([observation()]))
        let f = try XCTUnwrap(s.findings().first)
        XCTAssertEqual(f.intent, "UNKNOWN"); XCTAssertEqual(f.confidence, .high); XCTAssertFalse(f.eventIDs.isEmpty)
        let text = Explain.text(f, events: try s.events())
        for section in ["WHAT HAPPENED", "WHY IT WAS FLAGGED", "PROCESS / COMPONENT", "TIMELINE", "SUPPORTING EVIDENCE", "BASELINE DIFFERENCE", "OBSERVATION CONFIDENCE", "VISIBILITY LIMITATIONS", "SUGGESTED INVESTIGATION"] { XCTAssertTrue(text.contains(section)) }
        XCTAssertFalse(text.contains("malicious probability"))
    }
    func testIndependentCollectorFailureDoesNotAffectOtherSensor() throws {
        let s = try store(); try s.ingest(sample([], complete: false, state: .error))
        let other = SensorDescriptor("other", "Other", source: "fixture", monitors: "test")
        try s.ingest(CollectorSnapshot(descriptor: other, observations: [observation()], complete: true, state: .active, detail: "TEST"))
        XCTAssertEqual(try s.sensors().first { $0.id == "fixture" }?.state, .error)
        XCTAssertEqual(try s.sensors().first { $0.id == "other" }?.state, .active)
        XCTAssertEqual(try s.integrityCheck(), "ok")
    }
    func testStaleHealthIsNeverActive() {
        let health = SensorHealth(descriptor: descriptor, state: .active, visibility: .available, initialized: true, lastHeartbeat: Date(timeIntervalSince1970: 10))
        XCTAssertEqual(health.effective(at: Date(timeIntervalSince1970: 200)).state, .stopped)
        XCTAssertEqual(health.effective(at: Date(timeIntervalSince1970: 200)).visibility, .unknown)
    }
    func testSequenceGlobalGapAndReset() {
        var tracker = SequenceLossTracker(); let t = Date()
        XCTAssertNil(tracker.observe(version: 4, type: 1, sequence: 5, globalSequence: 40, at: t))
        XCTAssertEqual(tracker.observe(version: 4, type: 2, sequence: 100, globalSequence: 44, at: t.addingTimeInterval(1))?.lostCount, 3)
        XCTAssertNil(tracker.observe(version: 4, type: 2, sequence: 101, globalSequence: 45, at: t.addingTimeInterval(2)))
        XCTAssertNotNil(tracker.observe(version: 4, type: 2, sequence: 0, globalSequence: 0, at: t.addingTimeInterval(3)))
    }
    func testSequenceVersionGatingAndPerTypeTracking() {
        var tracker = SequenceLossTracker(); let t = Date()
        XCTAssertNil(tracker.observe(version: 1, type: 1, sequence: 8, globalSequence: 100, at: t))
        XCTAssertNil(tracker.observe(version: 2, type: 1, sequence: 10, globalSequence: 300, at: t))
        XCTAssertNil(tracker.observe(version: 2, type: 2, sequence: 99, globalSequence: 900, at: t))
        XCTAssertEqual(tracker.observe(version: 2, type: 1, sequence: 13, globalSequence: 999, at: t)?.lostCount, 2)
    }
    func testCorrelatesOnlyWithExecutableAndProcessInstanceEvidence() {
        let t = Date(), p = ProcessIdentity(pid: 42, uid: 501, executablePath: "/tmp/fixture", launchTime: Date(timeIntervalSince1970: 50))
        func event(_ cls: EventClass, _ delta: Double, _ process: ProcessIdentity?) -> EvidenceEvent {
            let o = Observation(key: UUID().uuidString, eventClass: cls, component: "TEST ONLY", attributes: ["executable": "/tmp/fixture"], process: process)
            return EvidenceEvent(timestamp: t.addingTimeInterval(delta), sourceCollector: cls.rawValue, eventType: "NEW", observation: o, currentState: o.attributes, baselineStatus: .new)
        }
        let persistence = event(.persistence, 0, nil), process = event(.process, 1, p), network = event(.network, 2, p)
        XCTAssertEqual(CorrelationEngine.correlate([persistence, process, network]).count, 1)
        var reused = p; reused.launchTime = Date(timeIntervalSince1970: 100)
        XCTAssertTrue(CorrelationEngine.correlate([persistence, process, event(.network, 2, reused)]).isEmpty)
        XCTAssertTrue(CorrelationEngine.correlate([persistence, process, event(.network, 90, p)]).isEmpty)
        XCTAssertTrue(CorrelationEngine.correlate([persistence, network]).isEmpty)
    }
    func testSQLiteRoundTripAndConcurrentReaders() throws {
        let writer = try store(); try writer.ingest(sample([observation("quote'\nagent")]))
        let reader = try store()
        XCTAssertEqual(try reader.events().count, 1)
        XCTAssertEqual(try reader.inventory().first?.observation.key, "quote'\nagent")
        XCTAssertEqual(try reader.integrityCheck(), "ok")
    }
    func testDatabaseSymlinkRejected() throws {
        let target = directory.appendingPathComponent("real.sqlite"), link = directory.appendingPathComponent("link.sqlite")
        FileManager.default.createFile(atPath: target.path, contents: Data())
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        XCTAssertThrowsError(try EventStore(url: link))
    }
    func testLsofNormalizationIPv4IPv6AndUDP() throws {
        let path = try XCTUnwrap(Bundle.module.url(forResource: "lsof", withExtension: "txt", subdirectory: "Fixtures"))
        let data = try String(contentsOf: path).replacingOccurrences(of: "\\0", with: "\0").data(using: .utf8)!
        let result = LsofParser.parse(data)
        XCTAssertFalse(result.invalid); XCTAssertEqual(result.rows.count, 4)
        XCTAssertEqual(result.rows[0].state, "LISTEN"); XCTAssertEqual(result.rows[2].proto, "UDP"); XCTAssertNotEqual(result.rows[2].state, "LISTEN")
        XCTAssertEqual(LsofParser.address("[::1]:9090").address, "::1")
        XCTAssertTrue(LsofParser.parse(Data("p42\0f1\0PBOGUS\0".utf8)).invalid)
    }
    func testExtensionParserFailsClosed() throws {
        let path = try XCTUnwrap(Bundle.module.url(forResource: "extensions", withExtension: "txt", subdirectory: "Fixtures"))
        let parsed = ExtensionParser.parse(try String(contentsOf: path))
        XCTAssertTrue(parsed.recognized); XCTAssertEqual(parsed.observations.count, 2)
        XCTAssertEqual(parsed.observations.first?.attributes["teamID"], "ABC123XYZ9")
        XCTAssertFalse(ExtensionParser.parse("Permission denied").recognized)
        XCTAssertFalse(ExtensionParser.parse("0 extension(s)\nunexpected warning").recognized)
        XCTAssertTrue(ExtensionParser.parse("0 extension(s)\n").recognized)
    }
    func testProcessParserDoesNotCollectArguments() {
        let parsed = ProcessParser.parse(" 42 1 501 Thu Oct  1 09:00:00 2026 /Applications/Example App.app/Contents/MacOS/Example\n")
        XCTAssertEqual(parsed.invalid, 0); XCTAssertEqual(parsed.processes.first?.pid, 42)
        XCTAssertEqual(parsed.processes.first?.executablePath, "/Applications/Example App.app/Contents/MacOS/Example")
        XCTAssertNotNil(parsed.processes.first?.launchTime)
    }
    func testTerminalSanitizesControlSequencesAndASCIIFallback() throws {
        XCTAssertFalse(TerminalText.safe("name\u{1B}]52;c;secret\u{07}\u{202E}").contains("\u{1B}"))
        let view = try StoreView(store: store())
        let plain = ConsoleRenderer.render(view, width: 80, height: 50, ascii: true)
        XCTAssertTrue(plain.unicodeScalars.allSatisfy(\.isASCII)); XCTAssertFalse(plain.contains("\u{1B}"))
        XCTAssertTrue(plain.contains("UNKNOWN")); XCTAssertFalse(plain.contains("92%"))
        let compact = ConsoleRenderer.render(view, width: 40, height: 20, ascii: true)
        XCTAssertTrue(compact.split(separator: "\n").allSatisfy { $0.count <= 40 })
        XCTAssertTrue(TerminalText.wordmark.contains("=====================================================*"))
    }
    func testStandardTerminalKeepsArtworkSummaryAndControlsVisible() throws {
        let s = try store(), empty = try StoreView(store: s)
        try s.ingest(sample([observation()]))
        try s.ingest(sample([observation("agent", "/tmp/synthetic-change")]))
        try s.ingest(sample([], complete: false, state: .error))
        let populated = try StoreView(store: s)
        XCTAssertFalse(populated.findings.isEmpty)
        for view in [empty, populated] {
            for ascii in [false, true] {
                let screen = ConsoleRenderer.render(view, width: 80, height: 24, ascii: ascii)
                let art = ascii ? TerminalText.asciiWordmark : TerminalText.wordmark
                for row in art.components(separatedBy: "\n") { XCTAssertTrue(screen.contains(row), "Missing artwork row: \(row)") }
                XCTAssertTrue(screen.contains("HOST SECURITY WATCHDOG"))
                XCTAssertTrue(screen.contains("MODE STORE VIEW"))
                XCTAssertTrue(screen.contains(view.sensors.isEmpty ? "COVERAGE UNKNOWN" : "COVERAGE 1 CHECK FAILED"))
                XCTAssertTrue(screen.contains("LAST SAMPLE \(view.sampledAt)"))
                XCTAssertTrue(screen.contains("OPEN FINDINGS \(view.findings.count)"))
                XCTAssertTrue(screen.contains("Changes \(view.changes) (last 200 events)"))
                XCTAssertTrue(screen.contains("No findings does not establish safety."))
                XCTAssertTrue(screen.contains("ES loss UNKNOWN"))
                XCTAssertTrue(screen.contains("[c] coverage"))
                XCTAssertTrue(screen.contains("[q] quit"))
                XCTAssertTrue(screen.contains("tripwire> _"))
                if ascii { XCTAssertTrue(screen.unicodeScalars.allSatisfy(\.isASCII)) }
            }
        }
    }
    func testSequenceExactBoundaryVersions() {
        let t = Date()
        for version: UInt32 in [0, 1] {
            var tracker = SequenceLossTracker()
            XCTAssertNil(tracker.observe(version: version, type: 1, sequence: 0, globalSequence: 0, at: t))
            XCTAssertNil(tracker.observe(version: version, type: 1, sequence: 10, globalSequence: 10, at: t))
        }
        for version: UInt32 in [2, 3] {
            var tracker = SequenceLossTracker()
            XCTAssertNil(tracker.observe(version: version, type: 1, sequence: 0, globalSequence: 0, at: t))
            XCTAssertNil(tracker.observe(version: version, type: 1, sequence: 1, globalSequence: 99, at: t))
            XCTAssertEqual(tracker.observe(version: version, type: 1, sequence: 3, globalSequence: 100, at: t)?.lostCount, 1)
        }
        var tracker = SequenceLossTracker()
        XCTAssertNil(tracker.observe(version: 4, type: 1, sequence: 0, globalSequence: 0, at: t))
        XCTAssertEqual(tracker.observe(version: 4, type: 2, sequence: 0, globalSequence: 2, at: t)?.lostCount, 1)
    }
    func testSafeFileNeverFollowsSymlinkOrReadsFIFO() throws {
        let target = directory.appendingPathComponent("metadata.plist")
        let data = Data("synthetic private value".utf8)
        try data.write(to: target)
        let link = directory.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        let inspected = try SafeFile.inspect(link, hash: true)
        XCTAssertNil(inspected.data); XCTAssertNil(inspected.metadata["sha256"])
        XCTAssertEqual(try SafeFile.inspect(target, hash: true).metadata["sha256"], Digest.sha256(data))
        let fifo = directory.appendingPathComponent("fifo")
        XCTAssertEqual(mkfifo(fifo.path, 0o600), 0)
        XCTAssertNil(try SafeFile.inspect(fifo, hash: true).data)
    }
    func testSafeFileCapsMetadataReadSize() throws {
        let file = directory.appendingPathComponent("large")
        try Data(repeating: 0, count: 2 * 1024 * 1024 + 1).write(to: file)
        let inspected = try SafeFile.inspect(file, hash: true)
        XCTAssertNil(inspected.data); XCTAssertNil(inspected.metadata["sha256"])
        XCTAssertTrue(inspected.metadata["hash"]!.contains("NOT OBSERVABLE"))
    }
    func testAbsenceCanRemainUnknownEvenForUsableBaselineSnapshot() throws {
        let s = try store()
        var snapshot = sample([observation()]); snapshot.absenceReliable = false
        try s.ingest(snapshot)
        snapshot.observations = []; try s.ingest(snapshot)
        XCTAssertEqual(try s.inventory().first?.present, true)
        XCTAssertTrue(try s.findings().isEmpty)
    }
    func testCoverageGapClosesButHistoryIsPreserved() throws {
        let s = try store(), start = Date(), end = Date().addingTimeInterval(10)
        try s.recordGap(CoverageGap(collector: "watchdog", start: start, reason: "test stop"))
        try s.closeGaps(collector: "watchdog", at: end)
        let gaps = try s.gaps(); XCTAssertEqual(gaps.count, 1)
        XCTAssertEqual(gaps.first?.end?.timeIntervalSince1970 ?? 0, end.timeIntervalSince1970, accuracy: 0.001)
    }
    func testReturnToBaselineExplanationIsAccurate() throws {
        let s = try store(); try s.ingest(sample([observation()])); try s.ingest(sample([observation("agent", "/tmp/fixture")]))
        try s.ingest(sample([observation()], date: Date().addingTimeInterval(1)))
        let finding = try XCTUnwrap(s.findings().first)
        XCTAssertTrue(finding.baselineDifference.contains("matches the original"))
    }
    func testAllTerminalSizesStayInsideBounds() throws {
        let view = try StoreView(store: store())
        for (width, height) in [(1, 1), (10, 4), (20, 10), (40, 20), (79, 24), (80, 23), (80, 24), (80, 43), (80, 44), (120, 60)] {
            for ascii in [false, true] {
                let lines = ConsoleRenderer.render(view, width: width, height: height, ascii: ascii).split(separator: "\n")
                XCTAssertLessThanOrEqual(lines.count, height)
                XCTAssertTrue(lines.allSatisfy { $0.count <= width })
            }
        }
    }
    func testReadCommandCapturesStderrWithoutPersistingIt() {
        let result = ReadCommand.run("/usr/bin/printf", ["%s", "fixture value"])
        XCTAssertTrue(result.successful); XCTAssertEqual(result.text, "fixture value")
        let missing = ReadCommand.run("/does/not/exist", [])
        XCTAssertFalse(missing.successful)
    }

    func testUncleanCollectorSessionProducesGapEvenWithinStaleThreshold() async throws {
        let s = try store()
        try s.setMetadata("openCollectorSession", "synthetic-unclosed-session")
        try s.setMetadata("lastSample", String(Date().addingTimeInterval(-5).timeIntervalSince1970))
        let monitor = Monitor(store: s, collectors: [])
        try await monitor.sample()
        XCTAssertTrue(try s.gaps().contains { $0.reason.contains("without a recorded stop") })
        try monitor.stop()
        XCTAssertEqual(try s.metadata("openCollectorSession"), "")
    }
    func testOnlyOneCooperatingCollectorOwnerCanAcquireStore() throws {
        let s = try store(), a = Monitor(store: s, collectors: []), b = Monitor(store: s, collectors: [])
        try a.acquire(); XCTAssertThrowsError(try b.acquire())
        a.release(); XCTAssertNoThrow(try b.acquire()); b.release()
    }
    func testSelfIntegrityChangesBecomeExplainableFindings() throws {
        let s = try store()
        let original = Observation(key: "self", eventClass: .health, component: "test executable", attributes: ["sha256": "a"])
        let changed = Observation(key: "self", eventClass: .health, component: "test executable", attributes: ["sha256": "b"])
        try s.ingest(sample([original])); try s.ingest(sample([changed]))
        XCTAssertTrue(try s.findings().first?.title.contains("Watchdog integrity") == true)
        XCTAssertEqual(try s.findings().first?.intent, "UNKNOWN")
    }

    func testOpaquePersistenceFileRetainsMetadataAndExplicitUnknownHash() throws {
        let file = directory.appendingPathComponent("opaque-helper")
        try Data("SYNTHETIC TEST".utf8).write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o100], ofItemAtPath: file.path)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path) }
        let inspection = try PersistenceCollector.inspectMetadata(file)
        XCTAssertNil(inspection.data); XCTAssertNil(inspection.metadata["sha256"])
        XCTAssertTrue(inspection.metadata["hash"]!.contains("NOT OBSERVABLE"))
        XCTAssertNotNil(inspection.metadata["ownerUID"]); XCTAssertEqual(inspection.metadata["mode"], "0100")
    }

    func testReadOnlyFirstViewerDoesNotCreateDiskStateAndCanDiscoverWriter() throws {
        let url = directory.appendingPathComponent("missing/nested/events.sqlite")
        let reader = try EventStore(url: url, access: .readOnly)
        XCTAssertTrue(try reader.events().isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.deletingLastPathComponent().path))
        XCTAssertThrowsError(try reader.setMetadata("test", "value"))
        XCTAssertThrowsError(try reader.ingest(sample([observation()])))
        let writer = try EventStore(url: url)
        try writer.ingest(sample([observation()]))
        let view = try StoreView(store: reader)
        XCTAssertEqual(view.events.count, 1)
    }
    func testReadOnlyWALSnapshotRemainsCoherentDuringWriterCommit() throws {
        let writer = try store(); try writer.ingest(sample([observation()]))
        let reader = try EventStore(url: writer.url, access: .readOnly)
        try reader.readSnapshot {
            let first = try reader.inventory().first!.observation.attributes
            try writer.ingest(sample([observation("agent", "/tmp/changed-fixture")]))
            XCTAssertEqual(try reader.inventory().first!.observation.attributes, first)
            XCTAssertEqual(try reader.events().count, 1)
        }
        XCTAssertEqual(try reader.inventory().first?.observation.attributes["executable"], "/tmp/changed-fixture")
        XCTAssertEqual(try reader.events().count, 2)
        XCTAssertThrowsError(try reader.approve(key: "fixture:agent", expectedFingerprint: observation().fingerprint))
    }
    func testPrivateStoreModesAndInsecureFileRejectionWithoutChmod() throws {
        let s = try store(); try s.ingest(sample([observation()]))
        for suffix in ["", "-wal", "-shm"] {
            let attrs = try FileManager.default.attributesOfItem(atPath: s.url.path + suffix)
            XCTAssertEqual((attrs[.posixPermissions] as! NSNumber).intValue & 0o077, 0)
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: s.url.path)
        XCTAssertThrowsError(try EventStore(url: s.url, access: .readOnly))
        XCTAssertThrowsError(try EventStore(url: s.url))
        let attrs = try FileManager.default.attributesOfItem(atPath: s.url.path)
        XCTAssertEqual((attrs[.posixPermissions] as! NSNumber).intValue, 0o644)
    }
    func testForeignFileIsRejectedWithoutModification() throws {
        let file = directory.appendingPathComponent("foreign.sqlite"), bytes = Data("SYNTHETIC non-database file".utf8)
        try bytes.write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        XCTAssertThrowsError(try EventStore(url: file))
        XCTAssertEqual(try Data(contentsOf: file), bytes)
    }
    func testFailedCompleteSnapshotCannotEstablishOrRemoveBaseline() throws {
        let s = try store()
        try s.ingest(sample([], complete: true, state: .error))
        XCTAssertNil(try s.metadata("baseline:fixture"))
        try s.ingest(sample([observation()]))
        try s.ingest(sample([], complete: true, state: .error))
        XCTAssertEqual(try s.inventory().first?.present, true)
        XCTAssertTrue(try s.findings().isEmpty)
        XCTAssertEqual(try s.sensors().first?.state, .error)
        XCTAssertEqual(try s.sensors().first?.visibility, .unknown)
    }
    func testEmptyIncompleteActiveSnapshotIsNotHealthy() throws {
        let s = try store()
        try s.ingest(sample([], complete: false, state: .active))
        XCTAssertEqual(try s.sensors().first?.state, .error)
        XCTAssertNil(try s.sensors().first?.lastSuccess)
    }
    func testScopeNarrowingNeverInventsOutOfScopeRemovals() throws {
        let s = try store(); try s.ingest(sample([observation("a"), observation("b")]))
        var narrower = sample([observation("a")]); narrower.descriptor.monitors = "Only scope a now"
        try s.ingest(narrower); try s.ingest(narrower)
        XCTAssertEqual(try s.inventory().first { $0.observation.key == "b" }?.present, true)
        XCTAssertFalse(try s.events().contains { $0.eventType == "REMOVED" })
        narrower.observations = []; try s.ingest(narrower)
        XCTAssertEqual(try s.inventory().first { $0.observation.key == "a" }?.present, false)
        XCTAssertEqual(try s.inventory().first { $0.observation.key == "b" }?.present, true)
    }
    func testApprovalRejectsStaleFingerprintWithoutAuditOrStatusChange() throws {
        let s = try store(); try s.ingest(sample([observation()]))
        let fingerprint = observation().fingerprint
        try s.ingest(sample([observation("agent", "/tmp/changed-fixture")]))
        XCTAssertThrowsError(try s.approve(key: "fixture:agent", expectedFingerprint: fingerprint))
        XCTAssertEqual(try s.inventory().first?.baselineStatus, .changed)
        XCTAssertFalse(try s.events().contains { $0.eventType == "APPROVAL" })
    }
    func testApprovalRollsBackIfAuditRecordCannotBeWritten() throws {
        let s = try store(); try s.ingest(sample([observation()]))
        var db: OpaquePointer?
        XCTAssertEqual(sqlite3_open(s.url.path, &db), SQLITE_OK)
        defer { sqlite3_close(db) }
        XCTAssertEqual(sqlite3_exec(db, "CREATE TRIGGER fail_audit BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END", nil, nil, nil), SQLITE_OK)
        XCTAssertThrowsError(try s.approve(key: "fixture:agent", expectedFingerprint: observation().fingerprint))
        XCTAssertNil(try s.inventory().first?.approvedFingerprint)
        XCTAssertEqual(try s.inventory().first?.baselineStatus, .known)
    }
    func testMissingOrFutureHeartbeatCannotDisplayActive() {
        let now = Date()
        let missing = SensorHealth(descriptor: descriptor, state: .active, visibility: .available)
        XCTAssertEqual(missing.effective(at: now).state, .stopped)
        let future = SensorHealth(descriptor: descriptor, state: .active, visibility: .available, initialized: true, lastHeartbeat: now.addingTimeInterval(30))
        XCTAssertEqual(future.effective(at: now).state, .stopped)
        XCTAssertEqual(future.effective(at: now).visibility, .unknown)
    }
    func testCanaryDirectoryRejectsSymlinkAndSharedPermissions() throws {
        let target = directory.appendingPathComponent("private"), link = directory.appendingPathComponent("link")
        try FileManager.default.createDirectory(at: target, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        XCTAssertNoThrow(try SafeFile.requirePrivateDirectory(target))
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        XCTAssertThrowsError(try SafeFile.requirePrivateDirectory(link))
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: target.path)
        XCTAssertThrowsError(try SafeFile.requirePrivateDirectory(target))
    }

    func testReadOnlyViewerCannotAcquireCollectorLock() throws {
        let writer = try store()
        let reader = try EventStore(url: writer.url, access: .readOnly)
        let monitor = Monitor(store: reader, collectors: [])
        XCTAssertThrowsError(try monitor.acquire())
        XCTAssertFalse(FileManager.default.fileExists(atPath: writer.url.path + ".collector-lock"))
    }

    func testExtensionCountMismatchAndDuplicateIdentityAreIncomplete() {
        let row = "* * ABC123XYZ9 com.example.fixture (1.0/1) Fixture [activated enabled]"
        XCTAssertFalse(ExtensionParser.parse("2 extension(s)\n" + row).recognized)
        XCTAssertFalse(ExtensionParser.parse("2 extension(s)\n" + row + "\n" + row).recognized)
        XCTAssertTrue(ExtensionParser.parse("1 extension(s)\n" + row).recognized)
    }

}
