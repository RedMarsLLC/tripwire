import Foundation

/// Local setup evidence is separate from delivered reports and never proves coverage.
public struct AgentSourceSetup: Sendable, Identifiable {
    public enum State: String, Sendable { case entriesFound, notFound, unreadable, external }
    public var id: AgentProvider { provider }
    public let provider: AgentProvider
    public let state: State
    public let events: [String]
    public init(provider: AgentProvider, state: State, events: [String] = []) {
        self.provider = provider; self.state = state; self.events = events
    }
    public var explanation: String {
        switch state {
        case .entriesFound: return "TripWire hook entries found for \(events.count) event types. Enabled state, provider trust and delivery must be verified by actual reports."
        case .notFound: return "No TripWire entries found in the default user hook configuration. Project-specific or other configuration locations were not checked."
        case .unreadable: return "Default user hook configuration could not be inspected. Setup is unknown."
        case .external: return "Requires an instrumented producer using the generic metadata contract. No automatic machine-wide feed."
        }
    }
}

public extension AgentReceipt {
    var actionDescription: String {
        switch event {
        case "SessionStart": return "Session started"
        case "SessionEnd": return "Session ended"
        case "UserPromptSubmit": return "Turn started"
        case "PreToolUse": return "Tool started: \(tool ?? "Unknown tool")"
        case "PostToolUse": return "Tool completion reported: \(tool ?? "Unknown tool")"
        case "PostToolUseFailure": return "Tool failure reported: \(tool ?? "Unknown tool")"
        case "PermissionRequest": return "Approval requested: \(tool ?? "Unknown tool")"
        case "Stop", "SubagentStop": return "Turn ended"
        case "Interrupt", "StopFailure": return "Turn interrupted"
        case "SubagentStart": return "Subagent started"
        default: return event
        }
    }
}

public extension AgentActivityView {
    func forProvider(_ provider: AgentProvider) -> Self {
        let matches = reports.filter { $0.provider == provider }
        return Self(reports: matches, error: error, truncated: truncated,
                    latestEvent: identities.first { $0.provider == provider })
    }
    /// Shared wording for the dashboard and overlay. Zero reports is never idle.
    func feedTitle(at date: Date) -> String {
        if error != nil { return "EVIDENCE UNAVAILABLE" }
        if truncated { return "LIMITED REPORT WINDOW" }
        guard hasRecentReport(at: date) else { return hasReports ? "NO RECENT REPORTS" : "AWAITING REPORTS" }
        let count = completions(at: date).count
        return count == 0 ? "EVENT RECEIVED" : "\(count) \(count == 1 ? "report" : "reports") / 60s"
    }
}

/// Sample each identity independently. Selecting an identity must never show the
/// aggregate trace or fabricate history from reports that have only just arrived.
public struct AgentActivityHistory: Sendable {
    public private(set) var all = MetricHistory()
    public private(set) var identities: [String: MetricHistory] = [:]
    public init() {}
    public func points(for identity: String?) -> [MetricPoint] {
        identity.map { identities[$0]?.points ?? [] } ?? all.points
    }
    public mutating func ingest(_ view: AgentActivityView, at date: Date) {
        func point(_ selected: AgentActivityView) -> MetricPoint {
            MetricPoint(timestamp: date, value: selected.hasRecentReport(at: date) ? Double(selected.completions(at: date).count) : nil)
        }
        all.append(point(view))
        let recent = Array(view.identities.prefix(128)).map(\.identity)
        identities = identities.filter { recent.contains($0.key) }
        for identity in recent {
            var history = identities[identity] ?? MetricHistory()
            history.append(point(view.selecting(identity)))
            identities[identity] = history
        }
    }
    public mutating func interrupt(at date: Date) {
        all.append(MetricPoint(timestamp: date, value: nil))
        for identity in Array(identities.keys) {
            identities[identity]?.append(MetricPoint(timestamp: date, value: nil))
        }
    }
}
