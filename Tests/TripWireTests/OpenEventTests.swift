import XCTest
import Darwin
import EndpointSecurity
@testable import TripWireCore
@testable import TripWireCollectors

final class OpenEventTests: XCTestCase {
    let stamp = Date(timeIntervalSince1970: 1_800_000_000)
    func fixture(path: String = "/test-only/protected/file", directory: Bool = false, sequence: Int = 20) throws -> Data {
        let format = ISO8601DateFormatter(); format.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let token: [String: Any] = ["pid": 200, "pidversion": 7, "ruid": 501]
        return try JSONSerialization.data(withJSONObject: ["schema_version": 1, "version": 4, "event_type": ES_EVENT_TYPE_NOTIFY_OPEN.rawValue, "global_seq_num": sequence, "seq_num": sequence, "time": format.string(from: stamp),
            "process": ["audit_token": token, "responsible_audit_token": ["pid": 100, "pidversion": 5, "ruid": 501], "executable": ["path": "/test-only/tool", "path_truncated": false], "ppid": 150, "start_time": format.string(from: stamp.addingTimeInterval(-5)), "args": ["NEVER RETAIN THIS"], "env": ["NEVER RETAIN THIS"]],
            "event": ["open": ["fflag": 1, "file": ["path": path, "path_truncated": false, "stat": ["st_mode": (directory ? S_IFDIR : S_IFREG) | 0o600]], "payload": "NEVER RETAIN THIS"]]])
    }
    func testBriefOpenWithExitedChildUsesResponsibleIdentityAndTriggersAlert() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("tripwire-open-test-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try EventStore(url: root.appendingPathComponent("events.sqlite"))
        // The event timestamp follows configuration, without touching the protected path.
        try store.saveTripwire(TripwireRule(name: "TEST protected folder", path: "/test-only/protected", kind: .folder))
        var rules = try store.tripwireRules(); rules[0].updatedAt = stamp.addingTimeInterval(-1)
        let row = try OpenEventRecord.decode(fixture())
        let observation = try XCTUnwrap(row.observation(session: "TEST", since: stamp.addingTimeInterval(-2), now: stamp, uid: 501, rules: rules, associate: { $0.pid == 100 && $0.pidversion == 5 ? "TEST AI" : nil }))
        XCTAssertEqual(observation.attributes["openMode"], "Read-capable")
        XCTAssertTrue(observation.attributes["associationBasis"]!.contains("responsible"))
        XCTAssertFalse(String(decoding: try JSONEncoder.stable.encode(observation), as: UTF8.self).contains("NEVER RETAIN"))
        // Use a current timestamp for ingest's actual persisted configuration revision.
        let snapshot = CollectorSnapshot(descriptor: OpenEventBridge.descriptor, timestamp: Date().addingTimeInterval(1), observations: [observation], complete: false, absenceReliable: false, state: .degraded, visibility: .limited, detail: "TEST ONLY")
        try store.ingest(snapshot); try store.ingest(snapshot)
        let finding = try XCTUnwrap(store.findings().first)
        XCTAssertEqual(try store.findings().count, 1); XCTAssertTrue(finding.whatHappened.contains("reported opening")); XCTAssertEqual(finding.intent, "UNKNOWN")
        XCTAssertTrue(finding.limitations.contains { $0.contains("not bytes") })
        XCTAssertNotNil(try store.event(id: XCTUnwrap(finding.eventIDs.first)))
        let distinct = try OpenEventRecord.decode(fixture(sequence: 21)).observation(session: "TEST", since: stamp.addingTimeInterval(-2), now: stamp, uid: 501, rules: rules, associate: { $0.pid == 100 ? "TEST AI" : nil })!
        var next = snapshot; next.observations = [distinct]; try store.ingest(next)
        XCTAssertEqual(try store.findings().count, 2, "Separate opens are separate events, unlike repeated handle snapshots")
    }
    func testRejectsStaleForeignUnattributedOutsideAndTruncatedInput() throws {
        let rule = TripwireRule(name: "TEST", path: "/test-only/protected", kind: .folder)
        let row = try OpenEventRecord.decode(fixture())
        XCTAssertNil(row.observation(session: "TEST", since: stamp.addingTimeInterval(-2), now: stamp, uid: 501, rules: [rule], associate: { _ in nil }))
        XCTAssertNil(row.observation(session: "TEST", since: stamp.addingTimeInterval(-2), now: stamp.addingTimeInterval(11), uid: 501, rules: [rule], associate: { _ in "TEST" }))
        XCTAssertNil(row.observation(session: "TEST", since: stamp.addingTimeInterval(1), now: stamp, uid: 501, rules: [rule], associate: { _ in "TEST" }))
        XCTAssertNil(row.observation(session: "TEST", since: stamp.addingTimeInterval(-2), now: stamp, uid: 502, rules: [rule], associate: { _ in "TEST" }))
        XCTAssertNil(try OpenEventRecord.decode(fixture(path: "/test-only/protected-copy/file")).observation(session: "TEST", since: stamp.addingTimeInterval(-2), now: stamp, uid: 501, rules: [rule], associate: { _ in "TEST" }))
        var data = String(decoding: try fixture(), as: UTF8.self).replacingOccurrences(of: "\"path_truncated\":false", with: "\"path_truncated\":true")
        XCTAssertThrowsError(try OpenEventRecord.decode(Data(data.utf8)))
        data = String(decoding: try fixture(), as: UTF8.self).replacingOccurrences(of: "\"schema_version\":1", with: "\"schema_version\":99")
        XCTAssertThrowsError(try OpenEventRecord.decode(Data(data.utf8)))
        XCTAssertThrowsError(try OpenEventRecord.decode(Data(repeating: 32, count: 262_145)))
    }
    func testDirectoriesAreEventsAndOlderRulesDoNotRetroactivelyMatch() throws {
        var rule = TripwireRule(name: "TEST", path: "/test-only/protected", kind: .folder)
        let row = try OpenEventRecord.decode(fixture(path: rule.path, directory: true))
        let observation = try XCTUnwrap(row.observation(session: "TEST", since: stamp.addingTimeInterval(-1), now: stamp, uid: 501, rules: [rule], associate: { _ in "TEST" }))
        XCTAssertEqual(observation.attributes["objectType"], "Directory")
        let snapshot = CollectorSnapshot(descriptor: OpenEventBridge.descriptor, timestamp: stamp, observations: [observation], state: .degraded, visibility: .limited, detail: "TEST ONLY")
        rule.updatedAt = stamp.addingTimeInterval(1)
        XCTAssertTrue(TripwireMatcher.matches(snapshot, rules: [rule]).isEmpty)
        rule.updatedAt = stamp.addingTimeInterval(-1)
        XCTAssertEqual(TripwireMatcher.matches(snapshot, rules: [rule]).count, 1)
    }
    func testCurrentAccountScopeRetainsUnrecognizedProcessAndExplainsInputUnknown() throws {
        let rule = TripwireRule(name: "TEST account", path: "/test-only/protected", kind: .folder, scope: .currentUser)
        let row = try OpenEventRecord.decode(fixture())
        let observation = try XCTUnwrap(row.observation(session: "TEST", since: stamp.addingTimeInterval(-1), now: stamp, uid: 501, rules: [rule], associate: { _ in nil }))
        XCTAssertNil(observation.attributes["associatedApp"])
        XCTAssertTrue(AccessContext.isMonitoringAccount(observation))
        let snapshot = CollectorSnapshot(descriptor: OpenEventBridge.descriptor, timestamp: stamp, observations: [observation], state: .degraded, visibility: .limited, detail: "TEST ONLY")
        let aiOnly = TripwireRule(name: "TEST AI", path: rule.path, kind: .folder)
        XCTAssertEqual(TripwireMatcher.matches(snapshot, rules: [rule, aiOnly]).map { $0.rule.id }, [rule.id])
        XCTAssertNil(row.observation(session: "TEST", since: stamp.addingTimeInterval(-1), now: stamp, uid: 502, rules: [rule], associate: { _ in nil }))
        let evidence = EvidenceEvent(timestamp: stamp, sourceCollector: OpenEventBridge.id, eventType: "TEST", observation: observation, currentState: observation.attributes, baselineStatus: .unknown)
        let text = try XCTUnwrap(AccessContext.text(evidence))
        XCTAssertTrue(text.contains("UID 501")); XCTAssertTrue(text.contains("Mouse vs keyboard vs automation: Unknown"))
        XCTAssertTrue(text.contains("AI association: Unknown"))
    }
    func testMutationKindsAndRenameBoundaryRolesStayDistinct() throws {
        let rule = TripwireRule(name: "TEST account", path: "/test-only/protected", kind: .folder, scope: .currentUser)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: fixture()) as? [String: Any])
        let file: [String: Any] = ["path": rule.path + "/test", "path_truncated": false, "stat": ["st_mode": S_IFREG | 0o600]]
        for (type, name) in [(ES_EVENT_TYPE_NOTIFY_WRITE, "write"), (ES_EVENT_TYPE_NOTIFY_CLOSE, "close"), (ES_EVENT_TYPE_NOTIFY_UNLINK, "unlink")] {
            object["event_type"] = type.rawValue; object["event"] = [name: ["target": file, "modified": true]]
            let decoded = try OpenEventRecord.decode(JSONSerialization.data(withJSONObject: object))
            let row = try XCTUnwrap(decoded.observation(session: "TEST", since: stamp.addingTimeInterval(-1), now: stamp, uid: 501, rules: [rule], associate: { _ in nil }))
            XCTAssertFalse(row.attributes["operation"]!.hasPrefix("Open")); XCTAssertNil(row.attributes["openMode"])
        }
        object["event_type"] = ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue; object["event"] = ["close": ["target": file, "modified": false]]
        XCTAssertNil(try OpenEventRecord.decode(JSONSerialization.data(withJSONObject: object)).observation(session: "TEST", since: stamp.addingTimeInterval(-1), now: stamp, uid: 501, rules: [rule], associate: { _ in nil }))
        object["event_type"] = ES_EVENT_TYPE_NOTIFY_RENAME.rawValue
        object["event"] = ["rename": ["source": file, "destination_type": ES_DESTINATION_TYPE_NEW_PATH.rawValue, "destination": ["new_path": ["dir": ["path": rule.path, "path_truncated": false], "filename": "renamed"]]]]
        var rows = try OpenEventRecord.decode(JSONSerialization.data(withJSONObject: object)).observations(session: "TEST", since: stamp.addingTimeInterval(-1), now: stamp, uid: 501, rules: [rule], associate: { _ in nil })
        XCTAssertEqual(rows.count, 2); XCTAssertEqual(Set(rows.map(\.key)).count, 2)
        let exact = TripwireRule(name: "TEST exact", path: rule.path + "/test", kind: .file, scope: .currentUser)
        rows = try OpenEventRecord.decode(JSONSerialization.data(withJSONObject: object)).observations(session: "TEST", since: stamp.addingTimeInterval(-1), now: stamp, uid: 501, rules: [exact], associate: { _ in nil })
        XCTAssertEqual(rows.count, 1); XCTAssertEqual(rows.first?.attributes["pathRole"], "source")
        object["event_type"] = ES_EVENT_TYPE_NOTIFY_EXEC.rawValue
        XCTAssertThrowsError(try OpenEventRecord.decode(JSONSerialization.data(withJSONObject: object)))
    }
    func testInvalidStreamAndStopCannotAppearHealthy() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("tripwire-bridge-test-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try EventStore(url: root.appendingPathComponent("events.sqlite")), bridge = OpenEventBridge(store: store)
        try bridge.consume(Data("unsupported".utf8)); try bridge.heartbeat()
        XCTAssertEqual(try store.sensors().first?.visibility, .unknown); XCTAssertFalse(try store.gaps().isEmpty)
        try bridge.stop(); XCTAssertEqual(try store.sensors().first?.state, .stopped)
        XCTAssertTrue(try store.findings().isEmpty)
    }
}
