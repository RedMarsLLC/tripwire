import XCTest
import TripWireCore
import TripWireCollectors

final class AgentFeedTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 2000)
    private func report(_ session: String, provider: AgentProvider = .codex, event: String = "PostToolUse", offset: Double = 0) throws -> AgentReceipt {
        let data = try JSONSerialization.data(withJSONObject: ["session_id": session, "hook_event_name": event, "tool_name": "Bash", "tool_use_id": UUID().uuidString])
        return try AgentReceipt.parse(data, provider: provider, at: now.addingTimeInterval(offset))
    }
    func testPerIdentityTracesKeepCountsSeparateAndExpireWithoutInventedZero() throws {
        let first = try report("first"), second = try report("second", provider: .claudeCode)
        let next = try report("second", provider: .claudeCode, offset: 1)
        var history = AgentActivityHistory()
        let initial = AgentActivityView(reports: [first, second])
        history.ingest(initial, at: now)
        history.ingest(AgentActivityView(reports: [first, second, next]), at: now.addingTimeInterval(1))
        XCTAssertEqual(history.points(for: nil).compactMap(\.value), [2, 3])
        XCTAssertEqual(history.points(for: first.identity).compactMap(\.value), [1, 1])
        XCTAssertEqual(history.points(for: second.identity).compactMap(\.value), [1, 2])
        XCTAssertTrue(history.points(for: "not-observed").isEmpty)
        history.ingest(initial, at: now.addingTimeInterval(31))
        XCTAssertNil(history.points(for: first.identity).last?.value)
        XCTAssertNil(history.points(for: nil).last?.value)
        history.interrupt(at: now.addingTimeInterval(32))
        XCTAssertNil(history.points(for: second.identity).last?.value)
    }
    func testProviderAndIdentitySelectionDoNotBorrowFreshnessFromOtherAgents() throws {
        let old = try report("old", offset: -60), fresh = try report("new", provider: .claudeCode)
        let view = AgentActivityView(reports: [fresh, old])
        XCTAssertEqual(view.forProvider(.codex).feedTitle(at: now), "NO RECENT REPORTS")
        XCTAssertEqual(view.forProvider(.cursor).feedTitle(at: now), "AWAITING REPORTS")
        XCTAssertEqual(view.selecting(old.identity).latestEvent?.id, old.id)
        XCTAssertEqual(view.selecting(fresh.identity).feedTitle(at: now), "1 report / 60s")
        XCTAssertEqual(AgentActivityView(error: "Unreadable").feedTitle(at: now), "EVIDENCE UNAVAILABLE")
        XCTAssertEqual(AgentActivityView(reports: [fresh], truncated: true).feedTitle(at: now), "LIMITED REPORT WINDOW")
        XCTAssertEqual(try report("waiting", event: "PermissionRequest").actionDescription, "Approval requested: Bash")
    }
    func testSetupProbeRecognizesExactCommandsWithoutExecutingOrChangingConfig() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let executable = home.appendingPathComponent("dist/tripwire")
        let config = home.appendingPathComponent(".codex/hooks.json")
        try FileManager.default.createDirectory(at: config.deletingLastPathComponent(), withIntermediateDirectories: true)
        let value: [String: Any] = ["SECRET": "must not retain", "hooks": [
            "PostToolUse": [["hooks": [["type": "command", "command": executable.path + " agent-hook"]]]],
            "Stop": [["hooks": [["type": "command", "command": "echo " + executable.path + " agent-hook"]]]]
        ]]
        let data = try JSONSerialization.data(withJSONObject: value)
        try data.write(to: config)
        let result = AgentIntegrationProbe.inspect(home: home, executable: executable)
        XCTAssertEqual(result.first?.state, .entriesFound)
        XCTAssertEqual(result.first?.events, ["PostToolUse"])
        XCTAssertEqual(result.first { $0.provider == .claudeCode }?.state, .notFound)
        XCTAssertEqual(result.first { $0.provider == .generic }?.state, .external)
        XCTAssertEqual(try Data(contentsOf: config), data)
        XCTAssertFalse(FileManager.default.fileExists(atPath: home.appendingPathComponent("Library").path))
        XCTAssertFalse(AgentActivityView().hasRecentReport(at: now), "Configuration alone cannot establish delivery")
        try Data(repeating: 0, count: 1_048_577).write(to: config)
        XCTAssertEqual(AgentIntegrationProbe.inspect(home: home, executable: executable).first?.state, .unreadable)
        try Data("{invalid".utf8).write(to: config)
        XCTAssertEqual(AgentIntegrationProbe.inspect(home: home, executable: executable).first?.state, .unreadable)
    }
}
