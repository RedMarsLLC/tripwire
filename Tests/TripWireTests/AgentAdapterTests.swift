import XCTest
import TripWireCore

final class AgentAdapterTests: XCTestCase {
    let now = Date(timeIntervalSince1970: 2000)
    func payload(_ overrides: [String: Any] = [:]) throws -> Data {
        var data: [String: Any] = ["session_id":"session", "hook_event_name":"PostToolUse", "tool_name":"Bash", "tool_use_id":"one", "agent_id":"worker", "prompt":"SECRET-PROMPT", "tool_output":"SECRET-OUTPUT", "transcript_path":"SECRET-PATH"]
        data.merge(overrides) { _, new in new }
        return try JSONSerialization.data(withJSONObject: data)
    }
    func testProviderAndSubagentIdentitiesDoNotCollide() throws {
        let codex = try AgentReceipt.parse(payload(), at: now)
        let claude = try AgentReceipt.parse(payload(), provider: .claudeCode, at: now)
        let other = try AgentReceipt.parse(payload(["agent_id":"other"]), provider: .claudeCode, at: now)
        XCTAssertEqual(Set([codex.id, claude.id, other.id]).count, 3)
        XCTAssertEqual(Set([codex.identity, claude.identity, other.identity]).count, 3)
        for receipt in [codex, claude, other] {
            let encoded = String(decoding: try JSONEncoder().encode(receipt), as: UTF8.self)
            XCTAssertFalse(encoded.contains("SECRET"))
            XCTAssertFalse(encoded.contains("worker"))
        }
    }
    func testCursorCommonSchemaAndFailedToolCompletion() throws {
        let receipt = try AgentReceipt.parse(payload(["conversation_id":"conversation", "generation_id":"generation", "hook_event_name":"postToolUseFailure", "tool_name":"Shell"]), provider: .cursor, at: now)
        XCTAssertEqual(receipt.provider, .cursor)
        XCTAssertEqual(receipt.event, "PostToolUseFailure")
        XCTAssertEqual(receipt.kind, .process)
        XCTAssertTrue(receipt.isCompletion)
        XCTAssertThrowsError(try AgentReceipt.parse(payload(), provider: .cursor))
        let stop = try AgentReceipt.parse(payload(["conversation_id":"conversation", "hook_event_name":"stop", "status":"aborted"]), provider: .cursor, at: now)
        XCTAssertEqual(stop.state(at: now), "INTERRUPTED")
    }
    func testGenericContractIsVersionedAndRejectsMissingIdentity() throws {
        let data = Data(#"{"schema_version":1,"session_id":"s","agent_id":"a","event_id":"e","event":"tool.completed","tool_name":"custom"}"#.utf8)
        let receipt = try AgentReceipt.parse(data, provider: .generic, at: now)
        XCTAssertEqual(receipt.provider, .generic)
        XCTAssertEqual(receipt.kind, .tool)
        XCTAssertEqual(receipt.id, try AgentReceipt.parse(data, provider: .generic, at: now.addingTimeInterval(1)).id)
        XCTAssertThrowsError(try AgentReceipt.parse(payload(), provider: .generic))
        XCTAssertThrowsError(try AgentReceipt.parse(Data(#"{"schema_version":2,"session_id":"s","agent_id":"a","event_id":"e","event":"turn.ended"}"#.utf8), provider: .generic))
    }
    func testOneAgentStoppingDoesNotReportOtherAgentIdle() throws {
        let working = try AgentReceipt.parse(payload(["hook_event_name":"PreToolUse"]), at: now)
        let stopped = try AgentReceipt.parse(payload(["hook_event_name":"Stop", "agent_id":"other"]), at: now.addingTimeInterval(1))
        let view = AgentActivityView(reports: [working, stopped])
        XCTAssertEqual(view.identities.count, 2)
        XCTAssertTrue(view.hasRecentReport(at: now.addingTimeInterval(2)))
        XCTAssertFalse(view.hasRecentReport(at: now.addingTimeInterval(40)))
        XCTAssertFalse(AgentActivityView().hasRecentReport(at: now))
        XCTAssertTrue(view.lifecycle(at: now.addingTimeInterval(2)).contains("1 WORKING"))
        XCTAssertFalse(view.lifecycle(at: now.addingTimeInterval(2)).contains("IDLE"))
        XCTAssertTrue(view.lifecycle(at: now.addingTimeInterval(40)).contains("2 UNKNOWN"))
        XCTAssertEqual(view.selecting(working.identity).lifecycle(at: now.addingTimeInterval(2)), "WORKING REPORTED")
        XCTAssertEqual(view.selecting(working.identity).lifecycle(at: now.addingTimeInterval(31)), "STATE UNKNOWN")
    }
    func testHistoricalCodexReceiptDecodesWithoutNewFields() throws {
        let data = Data(#"{"id":"old","timestamp":0,"sessionHash":"hash","event":"Stop"}"#.utf8)
        let receipt = try JSONDecoder().decode(AgentReceipt.self, from: data)
        XCTAssertEqual(receipt.provider, .codex)
        XCTAssertEqual(receipt.identity, "codex:hash:main")
    }
    func testMultipleProvidersPersistAndShareEvidenceWithoutSyntheticFindings() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try EventStore(url: dir.appendingPathComponent("test.sqlite"))
        for provider in [AgentProvider.codex, .claudeCode] {
            let receipt = try AgentReceipt.parse(payload(), provider: provider, at: now)
            try store.recordAgentReceipt(receipt); try store.recordAgentReceipt(receipt)
            XCTAssertEqual(try store.event(id: receipt.id)?.currentState?["provider"], provider.rawValue)
        }
        let view = try store.agentActivity(now: now)
        XCTAssertEqual(view.identities.count, 2)
        XCTAssertEqual(view.completions(at: now).count, 2)
        XCTAssertTrue(try store.findings().isEmpty)
    }
    func testClaudeSubagentStopDoesNotEndMainIdentity() throws {
        let main = try AgentReceipt.parse(Data(#"{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"one"}"#.utf8), provider: .claudeCode, at: now)
        let child = try AgentReceipt.parse(Data(#"{"session_id":"s","hook_event_name":"SubagentStop","agent_id":"child"}"#.utf8), provider: .claudeCode, at: now)
        XCTAssertNotEqual(main.identity, child.identity)
        XCTAssertEqual(main.state(at: now), "WORKING REPORTED")
        XCTAssertEqual(child.state(at: now), "IDLE / TURN ENDED")
    }
}
