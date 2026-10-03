import Foundation

public enum BaselineEngine {
    public static func status(current: Observation, baseline: [String: String]?, approvedFingerprint: String?) -> BaselineStatus {
        if approvedFingerprint == current.fingerprint { return .userApproved }
        guard let baseline else { return .new }
        return baseline == current.attributes ? .known : .changed
    }
    public static func differences(_ old: [String: String]?, _ new: [String: String]?) -> [String] {
        let keys = Set((old ?? [:]).keys).union((new ?? [:]).keys).sorted()
        return keys.compactMap { key in
            let a = old?[key], b = new?[key]
            return a == b ? nil : "\(key): \(a ?? "ABSENT") -> \(b ?? "ABSENT")"
        }
    }
}
public enum FindingEngine {
    public static func make(_ event: EvidenceEvent) -> Finding? {
        if event.observation.eventClass == .file { return FileAccessReview.finding(event) }
        guard event.eventType != "INITIAL", event.eventType != "KNOWN", event.baselineStatus != .unknown else { return nil }
        let cls = event.observation.eventClass
        guard [.listener, .application, .persistence, .extensions, .configuration, .hardware, .canary, .health].contains(cls) else { return nil }
        let verb = event.eventType == "REMOVED" ? "no longer observed" : event.eventType == "NEW" ? "first observed after baseline" : "changed"
        let title: String
        switch cls {
        case .listener: title = event.eventType == "NEW" ? "Previously unseen listening service" : "Listening service \(verb)"
        case .application: title = "Application bundle \(verb)"
        case .persistence: title = "Persistence inventory \(verb)"
        case .extensions: title = "\(event.sourceCollector == "kernel-modules" ? "Loaded kernel module" : event.sourceCollector == "kernel-bundles" ? "Kernel bundle" : "System extension") \(verb)"
        case .configuration: title = "Security configuration \(verb)"
        case .hardware: title = "Hardware \(verb)"
        case .canary: title = "Local canary \(verb)"
        case .health: title = "Watchdog integrity metadata \(verb)"
        default: return nil
        }
        return Finding(timestamp: event.timestamp, title: title,
            whatHappened: "\(event.observation.component) was \(verb) in a periodic inventory.",
            whyFlagged: reason(for: event) + " Current baseline status: \(event.baselineStatus.rawValue). The responsible agent and malicious intent are unknown.",
            component: event.observation.component, eventIDs: [event.id],
            baselineDifference: event.baselineStatus == .known ? "Current state matches the original observed baseline; the previous observation differed." : BaselineEngine.differences(event.baselineState, event.currentState).joined(separator: "\n"),
            confidence: event.observation.confidence, severity: .notice,
            limitations: Array(Set(event.limitations + event.observation.limitations + ["Timestamp is detection time; the actual change occurred between observations.", "Responsible agent UNKNOWN: a periodic inventory does not identify who made this change. An active AI session or resource spike alone is not attribution."])).sorted(),
            suggestedInvestigation: ["Review before/after evidence and the sensor's scope.", "Check whether an expected installation, update, or user action explains the change.", "Confirm process identity and signing information using independent evidence before acting."], ruleID: "inventory-change-v1")
    }

    public static func reason(for event: EvidenceEvent) -> String {
        switch event.observation.eventClass {
        case .application: return "An application bundle appeared, changed or disappeared in a monitored applications folder. Review whether this matches software you intended to install, update or remove. The first baseline is an inventory, not an approval of existing apps."
        case .listener: return "The inventory of services accepting TCP connections changed. Review the local address, port and owning process. A listening socket does not establish external reachability or who caused it to open."
        case .extensions where event.sourceCollector == "kernel-modules": return "The loaded Linux kernel-module inventory changed. These modules can add privileged capabilities. Polling does not identify the installer, load time or responsible agent, and built-in drivers are outside this source."
        case .extensions where event.sourceCollector == "kernel-bundles": return "The installed kernel-bundle inventory changed. Kernel extensions can add privileged system capabilities. This source observes bundle metadata; it does not establish that code was created by an agent or loaded into the kernel."
        case .extensions: return "The system-extension registration inventory changed. Extensions can add system-level capabilities; registration or reported activation does not prove runtime health."
        case .persistence: return "Startup or persistence metadata changed. These entries can affect what runs automatically; file presence alone does not prove registration or execution."
        default: return "A transition was observed relative to the previous inventory. This establishes an observed change, not its intent."
        }
    }
}

public enum CorrelationEngine {
    /// Conservative association: requires matching executable paths and exact process instance for network evidence.
    /// Same path is evidence of association, not proof a persistence item launched the process.
    public static func correlate(_ events: [EvidenceEvent], window: TimeInterval = 30) -> [Finding] {
        let sorted = events.sorted { $0.timestamp < $1.timestamp }
        var results: [Finding] = []
        for persistence in sorted where persistence.observation.eventClass == .persistence && ["NEW", "CHANGED"].contains(persistence.eventType) {
            guard let target = persistence.currentState?["executable"], target.hasPrefix("/") else { continue }
            let related = sorted.filter { $0.timestamp >= persistence.timestamp && $0.timestamp.timeIntervalSince(persistence.timestamp) <= window }
            guard let process = related.first(where: { $0.observation.eventClass == .process && $0.observation.process?.executablePath == target && $0.eventType == "NEW" }),
                  let instance = process.observation.process?.instanceKey,
                  let network = related.first(where: { $0.observation.eventClass == .network && $0.observation.process?.instanceKey == instance && $0.eventType == "NEW" }) else { continue }
            let evidence = [persistence, process, network]
            results.append(Finding(timestamp: network.timestamp, title: "Correlated persistence, process and network observations",
                whatHappened: "A changed persistence item references an executable that was newly observed as a running process with a network socket.",
                whyFlagged: "Three evidence sources share an executable identity and a short observation window.", component: target,
                eventIDs: evidence.map(\.id), baselineDifference: "Persistence changed; process and socket newly observed.", confidence: .moderate, severity: .elevated,
                limitations: Array(Set(evidence.flatMap { $0.limitations + $0.observation.limitations } + ["Polling cannot establish launch causality or exact ordering.", "Path association does not prove that the persistence item launched this process.", "No malicious intent established."])).sorted(),
                suggestedInvestigation: ["Inspect all linked observations and verify the executable's identity.", "Review expected software installation activity and the persistence target."], ruleID: "persistence-process-network-v1"))
        }
        return results
    }
}

public struct SequenceLossTracker {
    private var global: UInt64?
    private var perType: [UInt32: UInt64] = [:]
    private var lastTime: Date?
    public init() {}
    /// Only feed serially ordered messages from one ES client session. Recreate on reconnect.
    public mutating func observe(version: UInt32, type: UInt32, sequence: UInt64?, globalSequence: UInt64?, at time: Date) -> CoverageGap? {
        var lost: UInt64 = 0
        var reset = false
        if version >= 4, let globalSequence {
            if let prior = global {
                if globalSequence > prior, globalSequence - prior > 1 { lost = globalSequence - prior - 1 }
                else if globalSequence <= prior { reset = true }
            }
            global = globalSequence
        } else if version >= 2, let sequence {
            if let prior = perType[type] {
                if sequence > prior, sequence - prior > 1 { lost = sequence - prior - 1 }
                else if sequence <= prior { reset = true }
            }
            perType[type] = sequence
        }
        defer { lastTime = time }
        guard lost > 0 || reset else { return nil }
        return CoverageGap(collector: "endpoint-security", start: lastTime ?? time, end: time, reason: reset ? "Sequence reset or out-of-order delivery; coverage uncertain" : "Endpoint Security sequence discontinuity", lostCount: reset ? nil : lost)
    }
}
