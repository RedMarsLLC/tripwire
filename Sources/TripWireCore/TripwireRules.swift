import Foundation

public enum TripwireKind: String, Codable, CaseIterable, Identifiable {
    case file, folder, application
    public var id: String { rawValue }
    public var label: String { rawValue.capitalized }
}

public enum TripwireScope: String, Codable, CaseIterable, Identifiable {
    case aiAssociated = "ai-associated", currentUser = "current-user"
    public var id: String { rawValue }
    public var label: String { self == .currentUser ? "Any process under my account" : "AI-associated processes only" }
}

/// User policy, stored only in TripWire's private database. Never opens the target.
public struct TripwireRule: Codable, Equatable, Identifiable {
    public var id: String
    public var revision: String
    public var name: String
    public var path: String
    public var kind: TripwireKind
    public var enabled: Bool
    public var updatedAt: Date?
    public var platform: HostPlatform
    // Nil preserves the scope of rules saved before scope selection was introduced.
    public var scope: TripwireScope?
    public var effectiveScope: TripwireScope { scope ?? .aiAssociated }
    public init(id: String = UUID().uuidString, name: String, path: String, kind: TripwireKind, enabled: Bool = true, platform: HostPlatform = .current, scope: TripwireScope = .aiAssociated) {
        self.id = id; revision = UUID().uuidString; self.name = name; self.path = path
        self.kind = kind; self.enabled = enabled; self.platform = platform; self.scope = scope
    }
    public func validated() throws -> Self {
        var copy = self
        copy.name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !copy.name.isEmpty, copy.name.count <= 100, !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              UUID(uuidString: id) != nil, UUID(uuidString: revision) != nil, let normalized = TripwirePath.normalize(path, platform: platform) else {
            throw TripWireError.message("Give the tripwire a name (1–100 characters) and an absolute file, folder or application path. Control characters and relative paths are not allowed.")
        }
        copy.path = normalized
        return copy
    }
    public var scopeDescription: String {
        let subject = effectiveScope == .currentUser ? "Any process under the monitoring account, including your own apps and unrecognized AI tools" : "Recognized AI-associated processes"
        let target = kind == .application ? "file activity inside this application or its executable observed running" : kind == .folder ? "file/directory activity at this path or inside its subfolders" : "activity at this exact file path"
        return "\(subject): \(target). Snapshots can miss brief activity; event capture needs separate setup. Mouse, keyboard and user intent are not observed."
    }
}

public enum TripwirePath {
    /// Lexical matching only. No target reads, symlink resolution or case assumptions on Unix.
    public static func normalize(_ value: String, platform: HostPlatform) -> String? {
        guard !value.isEmpty, value.utf8.count <= 4096, !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { return nil }
        var path = platform == .windows ? value.replacingOccurrences(of: "\\", with: "/") : value
        let prefix: String
        if platform == .windows {
            if path.hasPrefix("/"), path.dropFirst(2).hasPrefix(":") { path.removeFirst() }
            let chars = Array(path.utf8)
            guard chars.count >= 3, ((65...90).contains(chars[0]) || (97...122).contains(chars[0])), chars[1] == 58, chars[2] == 47, !path.dropFirst(2).contains(":") else { return nil }
            prefix = String(path.prefix(2)).lowercased() + "/"; path = String(path.dropFirst(3)).lowercased()
        } else {
            guard path.hasPrefix("/") else { return nil }; prefix = "/"; path.removeFirst()
        }
        var parts: [Substring] = []
        for part in path.split(separator: "/") {
            if part == "." { continue }
            if part == ".." { guard !parts.isEmpty else { return nil }; parts.removeLast() }
            else { parts.append(part) }
        }
        return prefix + parts.joined(separator: "/")
    }
    public static func matches(_ observed: String, rule: TripwireRule) -> Bool {
        guard let path = normalize(observed, platform: rule.platform), let root = normalize(rule.path, platform: rule.platform) else { return false }
        return matchesNormalized(path, root: root, kind: rule.kind)
    }
    static func matchesNormalized(_ path: String, root: String, kind: TripwireKind) -> Bool {
        let recursive = kind == .folder || (kind == .application && root.hasSuffix(".app"))
        return path == root || (recursive && path.hasPrefix(root.hasSuffix("/") ? root : root + "/"))
    }
}

struct TripwireMatch {
    var rule: TripwireRule
    var observation: Observation
    var association: String
    var path: String
    var key: String {
        let identity = observation.attributes["accessEventID"] ?? observation.process?.instanceKey ?? observation.key
        return "tripwire-hit:\(rule.id):\(rule.revision):" + Digest.sha256(Data((identity + "\n" + path + "\n" + observation.eventClass.rawValue).utf8))
    }
    func finding(event: EvidenceEvent) -> Finding {
        let action = observation.attributes["accessEventID"] != nil ? "was reported \(observation.attributes["operationAction"] ?? "opening") \(path) by the OS event stream (\(observation.attributes["openMode"] ?? observation.attributes["operation"] ?? "mode unknown"))" : observation.eventClass == .file ? "was observed holding \(path) open (\(observation.attributes["openMode"] ?? "mode unknown"))" : "was observed running from \(path)"
        return Finding(timestamp: event.timestamp, title: "Tripwire triggered: \(rule.name)",
            whatHappened: "Process \(observation.process?.pid.map(String.init) ?? "UNKNOWN") \(action). \(association)",
            whyFlagged: "Your enabled \(rule.kind.rawValue) tripwire ‘\(rule.name)’ matches \(rule.path). Scope: \(rule.effectiveScope.label). This alert is independent of baseline approval. It reports an observed boundary match, not a proven unauthorized action or malicious intent.",
            component: path, eventIDs: [event.id], baselineDifference: "User tripwire \(rule.id), revision \(rule.revision). Original baseline retained.",
            confidence: observation.confidence == .high ? .moderate : observation.confidence, severity: .elevated,
            limitations: Array(Set(event.limitations + observation.limitations + TripwireMatcher.limitations)).sorted(),
            suggestedInvestigation: ["Review the linked evidence for the holding/running executable, process identity, path and observation time.", "Compare this activity with work you authorized. An open handle can be inherited; a sampled parent chain does not prove an AI instruction or exact launch causality.", "Edit or disable this tripwire in Configuration if the boundary is no longer appropriate. TripWire alerts; it does not block access or terminate applications."], ruleID: "user-tripwire:" + rule.id)
    }
}

enum TripwireMatcher {
    static let limitations = ["Snapshot polling can miss brief access and processes. The optional event feed must be separately authorized and running. AI-only rules can miss unrecognized agents and detached launches. Current-account rules include those tools when observed; protected processes and other accounts can remain outside scope.", "Paths are compared lexically. Aliases, hard links and symlink spellings may evade matching; target contents are never read.", "AI association uses app recognition and observed ancestry or OS-reported audit identities, not signature attestation, proof of an AI instruction or malicious intent.", "Repeated snapshots of the same process/path produce one alert per rule revision; a new process instance, rule revision or distinct event-feed operation can alert again."]
    static func matches(_ snapshot: CollectorSnapshot, rules: [TripwireRule], platform: HostPlatform = .current) -> [TripwireMatch] {
        // Valid observed rows from a partial source remain evidence, but unavailable sources do not.
        guard snapshot.visibility != .unavailable, snapshot.visibility != .notObservable else { return [] }
        let active = rules.filter { $0.enabled && $0.platform == platform && (snapshot.descriptor.id != "file-open-events" || $0.updatedAt == nil || snapshot.timestamp >= $0.updatedAt!) }.compactMap { rule in TripwirePath.normalize(rule.path, platform: platform).map { (rule, $0) } }
        guard !active.isEmpty else { return [] }
        let processes = Dictionary(snapshot.observations.compactMap { row in row.process?.pid.map { ($0, row.process!) } }, uniquingKeysWith: { a, _ in a })
        var results: [TripwireMatch] = []
        for row in snapshot.observations {
            var association: String?, path: String?
            if ["ai-open-files", "file-open-events"].contains(snapshot.descriptor.id), row.eventClass == .file {
                path = row.attributes["path"]
                if let app = row.attributes["associatedApp"], !app.isEmpty, let basis = row.attributes["associationBasis"] {
                    association = "Associated app: \(app). \(basis)"
                }
            } else if snapshot.descriptor.id == "processes", row.eventClass == .process, let process = row.process {
                association = aiAncestor(process, processes: processes, platform: platform); path = process.executablePath
            }
            guard let path, let normalized = TripwirePath.normalize(path, platform: platform) else { continue }
            for (rule, root) in active where (row.eventClass == .file || rule.kind == .application) && TripwirePath.matchesNormalized(normalized, root: root, kind: rule.kind) {
                if rule.effectiveScope == .aiAssociated && association == nil { continue }
                if rule.effectiveScope == .currentUser && !AccessContext.isMonitoringAccount(row) { continue }
                let basis = association ?? "Process account matches the monitoring account. AI association is unknown; this rule does not require one."
                results.append(TripwireMatch(rule: rule, observation: row, association: basis, path: path))
            }
        }
        return results
    }
    static func aiAncestor(_ start: ProcessIdentity, processes: [Int32: ProcessIdentity], platform: HostPlatform) -> String? {
        let names: Set<String> = ["codex", "chatgpt", "claude", "cursor", "ollama", "lm-studio", "lm studio"]
        var next = start, visited = Set<Int32>()
        while let pid = next.pid, visited.insert(pid).inserted, visited.count <= 32 {
            guard next.instanceKey != nil, let path = next.executablePath else { return nil }
            let parts = path.replacingOccurrences(of: "\\", with: "/").lowercased().split(separator: "/").map(String.init)
            let last = parts.last ?? "", leaf = last.hasSuffix(".exe") ? String(last.dropLast(4)) : last
            let recognized = platform == .macOS ? parts.contains(where: { $0.hasSuffix(".app") && names.contains(String($0.dropLast(4))) }) : names.contains(leaf)
            if recognized { return "Observed process chain to \(path) (PID \(pid)); recognition is not attestation." }
            guard let parentID = next.parentPID, let parent = processes[parentID],
                  let parentTime = parent.launchTime, let childTime = next.launchTime, parentTime <= childTime,
                  (next.uid != nil && next.uid == parent.uid) || (next.accountID != nil && next.accountID == parent.accountID) else { return nil }
            next = parent
        }
        return nil
    }
}
