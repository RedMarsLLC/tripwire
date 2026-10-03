import XCTest
import TripWireCore
import TripWireCollectors

final class CodexActivityTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 2000)
    private func input(event: String = "PostToolUse", tool: String = "Bash", id: String = "tool-1") throws -> Data {
        try JSONSerialization.data(withJSONObject: ["session_id": "fixture-session", "turn_id": "turn-1", "hook_event_name": event,
            "tool_name": tool, "tool_use_id": id, "tool_input": ["command": "DO-NOT-STORE-SECRET"], "tool_response": "PRIVATE-OUTPUT",
            "transcript_path": "/DO-NOT-READ", "last_assistant_message": "PRIVATE-MESSAGE"])
    }
    func testHookParserRetainsOnlyMetadataAndDoesNotReadTranscript() throws {
        let receipt = try CodexHookReceipt.parse(input(), at: now)
        let encoded = String(decoding: try JSONEncoder().encode(receipt), as: UTF8.self)
        for secret in ["DO-NOT-STORE-SECRET", "PRIVATE-OUTPUT", "/DO-NOT-READ", "PRIVATE-MESSAGE", "fixture-session"] { XCTAssertFalse(encoded.contains(secret)) }
        XCTAssertEqual(receipt.kind, .process)
        XCTAssertEqual(receipt.event, "PostToolUse")
        XCTAssertEqual(receipt.timestamp, now)
    }
    func testPermissionRequestNeedsNoToolUseIDAndNeverMeansGranted() throws {
        let data = Data(#"{"session_id":"session","hook_event_name":"PermissionRequest","tool_name":"Bash"}"#.utf8)
        let receipt = try CodexHookReceipt.parse(data, at: now)
        XCTAssertEqual(receipt.kind, .approval)
        XCTAssertEqual(receipt.event, "PermissionRequest")
        XCTAssertTrue(CodexHookView(reports: [receipt], latestReport: now).completions(at: now).isEmpty)
    }
    func testHookInputBoundsAndIdentifiersFailClosed() throws {
        XCTAssertThrowsError(try CodexHookReceipt.parse(Data(repeating: 32, count: 1_048_577)))
        XCTAssertThrowsError(try CodexHookReceipt.parse(input(event: "InventedEvent")))
        XCTAssertThrowsError(try CodexHookReceipt.parse(input(tool: "Bash\nESC")))
        XCTAssertThrowsError(try CodexHookReceipt.parse(Data(#"{"session_id":"s","hook_event_name":"PostToolUse","tool_name":"Bash"}"#.utf8)))
    }
    func testUnknownToolIsGenericNotInventedNetworkActivity() throws {
        XCTAssertEqual(try CodexHookReceipt.parse(input(tool: "mcp__web__fetch")).kind, .tool)
        XCTAssertEqual(try CodexHookReceipt.parse(input(tool: "apply_patch")).kind, .file)
    }
    func testHookReportsDeduplicateAndLinkToSharedEvidence() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try EventStore(url: dir.appendingPathComponent("events.sqlite"))
        let receipt = try CodexHookReceipt.parse(input(), at: now)
        try store.recordCodexHook(receipt); try store.recordCodexHook(receipt)
        XCTAssertEqual(try store.codexHooks(now: now).completions(at: now).count, 1)
        let evidence = try XCTUnwrap(store.event(id: receipt.id))
        XCTAssertEqual(evidence.id, receipt.id)
        XCTAssertEqual(evidence.sourceCollector, "codex-hooks")
        XCTAssertEqual(evidence.currentState?["process"], "UNKNOWN")
        XCTAssertEqual(try store.findings().count, 0)
        let reader = try EventStore(url: store.url, access: .readOnly)
        XCTAssertThrowsError(try reader.recordCodexHook(receipt))
        XCTAssertTrue(try reader.codexHooks(now: now.addingTimeInterval(61)).completions(at: now.addingTimeInterval(61)).isEmpty)
    }
    func testSmoothTimeAxisMovesExistingPointsWithoutAddingMeasurements() {
        let point = MetricPoint(timestamp: now, value: 30)
        XCTAssertEqual(MetricPlot.x(timestamp: point.timestamp, now: now, width: 240), 240)
        XCTAssertEqual(MetricPlot.x(timestamp: point.timestamp, now: now.addingTimeInterval(0.25), width: 240), 239, accuracy: 0.001)
        XCTAssertFalse(MetricPlot.canJoin(previous: point, current: MetricPoint(timestamp: now.addingTimeInterval(5), value: 40)))
        XCTAssertFalse(MetricPlot.canJoin(previous: point, current: MetricPoint(timestamp: now.addingTimeInterval(1), value: nil)))
        XCTAssertTrue(MetricPlot.canJoin(previous: point, current: MetricPoint(timestamp: now.addingTimeInterval(1), value: 40)))
    }
    func testLifecycleReportsNeverInferIdleFromSilence() throws {
        let pairs = [("UserPromptSubmit", "WORKING REPORTED"), ("PreToolUse", "WORKING REPORTED"), ("PermissionRequest", "WAITING FOR APPROVAL"), ("Stop", "IDLE / TURN ENDED"), ("Interrupt", "INTERRUPTED"), ("SessionEnd", "SESSION ENDED")]
        for (event, expected) in pairs {
            let receipt = try CodexHookReceipt.parse(input(event: event), at: now)
            let view = CodexHookView(reports: [receipt], latestReport: now)
            XCTAssertEqual(view.lifecycle(at: now), expected)
            XCTAssertEqual(view.lifecycle(at: now.addingTimeInterval(31)), "STATE UNKNOWN")
            XCTAssertTrue(view.lastEventText(at: now).contains("UTC"))
        }
        XCTAssertEqual(CodexHookView().lifecycle(at: now), "STATE UNKNOWN")
        XCTAssertEqual(CodexHookView().lastEventText(at: now), "LAST EVENT UNKNOWN")
    }
    func testPromptMetadataNeverRetainsPromptAndPreToolDoesNotCountTwice() throws {
        let receipt = try CodexHookReceipt.parse(Data(#"{"session_id":"fixture","hook_event_name":"UserPromptSubmit","prompt":"SECRET PROMPT"}"#.utf8), at: now)
        XCTAssertFalse(String(decoding: try JSONEncoder().encode(receipt), as: UTF8.self).contains("SECRET"))
        let pre = try CodexHookReceipt.parse(input(event: "PreToolUse"), at: now)
        let post = try CodexHookReceipt.parse(input(), at: now)
        XCTAssertEqual(CodexHookView(reports: [pre, post], latestReport: now).completions(at: now).count, 1)
    }
}
