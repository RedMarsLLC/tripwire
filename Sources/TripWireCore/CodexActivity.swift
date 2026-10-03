import Foundation

public enum AgentProvider: String, CaseIterable, Codable, Sendable {
    case codex, claudeCode = "claude-code", cursor, generic
    public var name: String {
        switch self { case .codex: return "Codex"; case .claudeCode: return "Claude Code"; case .cursor: return "Cursor"; case .generic: return "Generic agent" }
    }
}

/// Same-user application reports, not kernel-attested actions. Only allowlisted
/// metadata is decoded. Provider is selected by the invocation, not payload.
public struct AgentReceipt: Codable, Equatable, Sendable, Identifiable {
    public let id: String
    public let timestamp: Date
    public let sessionHash: String
    public let event: String
    public let tool: String?
    public let kind: AgentActivityKind?
    // Optional fields keep historical Codex receipts readable without rewriting evidence.
    public let providerID: AgentProvider?
    public let agentHash: String?
    public let turnHash: String?
    public var provider: AgentProvider { providerID ?? .codex }
    public var identity: String { provider.rawValue + ":" + sessionHash + ":" + (agentHash ?? "main") }
    public var label: String { provider.name + " / " + sessionHash.prefix(6) + (agentHash.map { " / " + $0.prefix(6) } ?? " / session") }
    public var isCompletion: Bool { ["PostToolUse", "PostToolUseFailure"].contains(event) }
    private struct Input: Decodable {
        let session_id: String?
        let conversation_id: String?
        let hook_event_name: String?
        let event: String?
        let event_id: String?
        let turn_id: String?
        let prompt_id: String?
        let generation_id: String?
        let agent_id: String?
        let tool_name: String?
        let tool_use_id: String?
        let status: String?
        let schema_version: Int?
    }
    public static func parse(_ data: Data, provider: AgentProvider = .codex, at date: Date = Date()) throws -> Self {
        guard data.count <= 1_048_576 else { throw TripWireError.message("Hook input exceeds metadata adapter limit") }
        let input = try JSONDecoder().decode(Input.self, from: data)
        func valid(_ value: String) -> Bool {
            !value.isEmpty && value.utf8.count <= 256 && value.unicodeScalars.allSatisfy { CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "._-:/")).contains($0) }
        }
        let sourceEvent = input.hook_event_name ?? input.event ?? ""
        let sessionID = provider == .cursor ? input.conversation_id : input.session_id
        let turnID = provider == .cursor ? input.generation_id : provider == .claudeCode ? input.prompt_id : input.turn_id
        var event = sourceEvent
        let codex = ["SessionStart", "SessionEnd", "UserPromptSubmit", "PreToolUse", "PostToolUse", "PermissionRequest", "Stop", "Interrupt"]
        switch provider {
        case .codex: guard codex.contains(event) else { throw TripWireError.message("Unsupported Codex event") }
        case .claudeCode:
            guard (codex.filter { $0 != "Interrupt" } + ["PostToolUseFailure", "StopFailure", "SubagentStart", "SubagentStop"]).contains(event) else { throw TripWireError.message("Unsupported Claude Code event") }
        case .cursor:
            let mapping = ["sessionStart":"SessionStart", "sessionEnd":"SessionEnd", "beforeSubmitPrompt":"UserPromptSubmit", "preToolUse":"PreToolUse", "postToolUse":"PostToolUse", "postToolUseFailure":"PostToolUseFailure", "stop":"Stop"]
            guard let mapped = mapping[event] else { throw TripWireError.message("Unsupported Cursor event") }
            event = mapped
            if event == "Stop", input.status != "completed" { event = "Interrupt" }
        case .generic:
            let mapping = ["session.started":"SessionStart", "session.ended":"SessionEnd", "turn.started":"UserPromptSubmit", "tool.started":"PreToolUse", "tool.completed":"PostToolUse", "tool.failed":"PostToolUseFailure", "approval.requested":"PermissionRequest", "turn.ended":"Stop", "turn.interrupted":"Interrupt"]
            guard input.schema_version == 1, let mapped = mapping[event], let agent = input.agent_id, valid(agent), let eventID = input.event_id, valid(eventID) else { throw TripWireError.message("Invalid generic v1 metadata") }
            event = mapped
        }
        guard let rawSession = sessionID, valid(rawSession), turnID.map(valid) ?? true,
              input.agent_id.map(valid) ?? true, input.event_id.map(valid) ?? true else { throw TripWireError.message("Invalid agent identity metadata") }
        let isTool = ["PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionRequest"].contains(event)
        if isTool {
            guard let tool = input.tool_name, valid(tool), input.tool_use_id.map(valid) ?? (event == "PermissionRequest" || provider == .generic) else { throw TripWireError.message("Tool report lacks valid metadata") }
        }
        let session = Digest.sha256(Data(rawSession.utf8))
        let agent = input.agent_id.map { Digest.sha256(Data($0.utf8)) }
        let turn = turnID.map { Digest.sha256(Data($0.utf8)) }
        let key = [provider.rawValue, session, agent ?? "main", turn ?? "", event, input.event_id ?? input.tool_use_id ?? String(date.timeIntervalSince1970)].joined(separator: ":")
        let complete = ["PostToolUse", "PostToolUseFailure"].contains(event)
        let kind: AgentActivityKind? = event == "PermissionRequest" ? .approval : complete ? (["Bash", "Shell"].contains(input.tool_name ?? "") ? .process : ["apply_patch", "Edit", "Write"].contains(input.tool_name ?? "") ? .file : .tool) : nil
        return Self(id: provider.rawValue + "-hook:" + Digest.sha256(Data(key.utf8)), timestamp: date, sessionHash: session, event: event,
                    tool: isTool ? input.tool_name : nil, kind: kind, providerID: provider, agentHash: agent, turnHash: turn)
    }
    /// A state report for this identity only; silence is unknown, never idle.
    public func state(at now: Date) -> String {
        guard (0...30).contains(now.timeIntervalSince(timestamp)) else { return "STATE UNKNOWN" }
        switch event {
        case "UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure", "SubagentStart": return "WORKING REPORTED"
        case "PermissionRequest": return "WAITING FOR APPROVAL"
        case "Stop", "SubagentStop": return "IDLE / TURN ENDED"
        case "Interrupt", "StopFailure": return "INTERRUPTED"
        case "SessionEnd": return "SESSION ENDED"
        default: return "STATE UNKNOWN"
        }
    }
}

public struct AgentActivityView: Sendable {
    public var reports: [AgentReceipt]
    public var latestReport: Date?
    public var latestEvent: AgentReceipt?
    public var error: String?
    public var truncated: Bool
    public init(reports: [AgentReceipt] = [], latestReport: Date? = nil, error: String? = nil, truncated: Bool = false, latestEvent: AgentReceipt? = nil) {
        self.latestEvent = latestEvent ?? reports.max(by: { $0.timestamp < $1.timestamp })
        self.reports = reports; self.latestReport = latestReport ?? self.latestEvent?.timestamp; self.error = error; self.truncated = truncated
    }
    /// Historical evidence exists. This is NOT a connectivity/heartbeat claim.
    public var hasReports: Bool { latestReport != nil && error == nil }
    public var connected: Bool { hasReports } // compatibility; never display as connected
    public func hasRecentReport(at now: Date) -> Bool {
        guard error == nil, !truncated, let latestReport else { return false }
        return (0...30).contains(now.timeIntervalSince(latestReport))
    }
    public func completions(at now: Date) -> [AgentReceipt] {
        reports.filter { $0.isCompletion && (0..<60).contains(now.timeIntervalSince($0.timestamp)) }
    }
    public var identities: [AgentReceipt] {
        var seen = Set<String>()
        return (reports + (latestEvent.map { [$0] } ?? [])).sorted { $0.timestamp > $1.timestamp }.filter { seen.insert($0.identity).inserted }
    }
    public func selecting(_ identity: String?) -> Self {
        guard let identity else { return self }
        let matches = reports.filter { $0.identity == identity }
        let latest = latestEvent?.identity == identity ? latestEvent : matches.max { $0.timestamp < $1.timestamp }
        return Self(reports: matches, error: error, truncated: truncated, latestEvent: latest)
    }
    public func lifecycle(at now: Date) -> String {
        guard error == nil, !truncated else { return "STATE UNKNOWN" }
        let agents = identities
        guard agents.count > 1 else { return agents.first?.state(at: now) ?? "STATE UNKNOWN" }
        let working = agents.filter { $0.state(at: now) == "WORKING REPORTED" }.count
        let waiting = agents.filter { $0.state(at: now) == "WAITING FOR APPROVAL" }.count
        let unknown = agents.filter { $0.state(at: now) == "STATE UNKNOWN" }.count
        return "\(working) WORKING · \(waiting) WAITING · \(unknown) UNKNOWN"
    }
    public func lastEventText(at now: Date) -> String {
        guard let latestEvent else { return "LAST EVENT UNKNOWN" }
        guard now >= latestEvent.timestamp else { return "LAST EVENT TIME UNCERTAIN" }
        return "LAST " + String(TimeText.iso(latestEvent.timestamp).suffix(9).prefix(8)) + " UTC"
    }
}
// Source compatibility for older clients; the store preserves original evidence.
public typealias CodexHookReceipt = AgentReceipt
public typealias CodexHookView = AgentActivityView

/// Rendering moves timestamps only. No invented samples or bridging gaps.
public enum MetricPlot {
    public static func x(timestamp: Date, now: Date, width: Double) -> Double {
        width * (1 - now.timeIntervalSince(timestamp) / MetricHistory.window)
    }
    public static func canJoin(previous: MetricPoint, current: MetricPoint) -> Bool {
        guard previous.value != nil, current.value != nil else { return false }
        let interval = current.timestamp.timeIntervalSince(previous.timestamp)
        return interval > 0 && interval <= ResourceMetrics.staleAfter
    }
}
