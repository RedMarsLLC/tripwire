import Foundation
import CSQLite

public enum StoreAccess { case readOnly, readWrite }

public final class EventStore {
    private var db: OpaquePointer?
    private let lock = NSRecursiveLock()
    private var waitingForStore = false
    public let url: URL
    public static var defaultURL: URL { HostPlatform.defaultStoreURL }
    public let access: StoreAccess
    public var isReadOnly: Bool { access == .readOnly }
    public init(url: URL = EventStore.defaultURL, access: StoreAccess = .readWrite) throws {
        self.url = url; self.access = access
        let directory = url.deletingLastPathComponent()
        let initialSize = try PrivateFiles.size(url.path)
        let exists = initialSize != nil
        if exists {
            try PrivateFiles.validate(url.path)
            for suffix in ["-wal", "-shm"] { try PrivateFiles.validate(url.path + suffix, missingAllowed: true) }
        }
        // A first-run viewer gets an empty in-memory schema. It creates no on-disk state.
        let memoryOnly = access == .readOnly && !exists
        waitingForStore = memoryOnly
        if access == .readWrite {
            try PrivateFiles.prepareDirectory(directory)
            if !exists { try PrivateFiles.create(url.path) }
        }
        let flags: Int32 = (memoryOnly ? SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE : access == .readOnly ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE) | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW
        var sqlitePath = ":memory:"
        if !memoryOnly {
            sqlitePath = try PrivateFiles.resolvedPath(url)
        }
        let opened = sqlite3_open_v2(sqlitePath, &db, flags, nil)
        guard opened == SQLITE_OK else {
            let reason = String(cString: sqlite3_errmsg(db))
            sqlite3_close(db); db = nil
            throw TripWireError.message("Cannot open event store with requested access (\(opened)): \(reason)")
        }
        sqlite3_busy_timeout(db, 5000)
        do {
            if exists && (initialSize ?? 0) > 0 {
                guard try scalar("SELECT value FROM metadata WHERE key='schema'") == "1" else { throw TripWireError.message("Unsupported or foreign event-store schema") }
            }
            if access == .readWrite || memoryOnly {
                if !memoryOnly { try execute("PRAGMA journal_mode=WAL"); try execute("PRAGMA synchronous=FULL") }
                try execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                try execute("INSERT OR IGNORE INTO metadata VALUES ('schema','1')")
                for table in ["events", "findings", "inventory", "sensors", "gaps", "agent_receipts"] {
                    try execute("CREATE TABLE IF NOT EXISTS \(table) (id TEXT PRIMARY KEY, timestamp REAL NOT NULL, json TEXT NOT NULL)")
                    try execute("CREATE INDEX IF NOT EXISTS \(table)_time ON \(table)(timestamp)")
                }
            }
            if access == .readOnly { try execute("PRAGMA query_only=ON") }
        } catch { sqlite3_close(db); db = nil; throw error }
    }
    private func requireWritable() throws {
        guard !isReadOnly else { throw TripWireError.message("Read-only event-store connection cannot modify evidence") }
    }
    public func readSnapshot<T>(_ body: () throws -> T) throws -> T {
        lock.lock(); defer { lock.unlock() }
        if waitingForStore {
            if try PrivateFiles.size(url.path) != nil {
                let replacement = try EventStore(url: url, access: .readOnly)
                sqlite3_close(db); db = replacement.db; replacement.db = nil
                waitingForStore = false
            }
        }
        try execute("BEGIN DEFERRED")
        do { let result = try body(); try execute("COMMIT"); return result }
        catch { try? execute("ROLLBACK"); throw error }
    }
    deinit { sqlite3_close(db) }
    private func execute(_ sql: String) throws {
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw TripWireError.message("SQLite: \(String(cString: sqlite3_errmsg(db)))") }
    }
    private func query(_ sql: String, bindings: [String] = []) throws -> [[String]] {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else { throw TripWireError.message("SQLite prepare failed") }
        defer { sqlite3_finalize(statement) }
        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        for (i, binding) in bindings.enumerated() { sqlite3_bind_text(statement, Int32(i + 1), binding, -1, transient) }
        var rows: [[String]] = []
        while true {
            let result = sqlite3_step(statement)
            if result == SQLITE_DONE { break }
            guard result == SQLITE_ROW else { throw TripWireError.message("SQLite step failed: \(String(cString: sqlite3_errmsg(db)))") }
            rows.append((0..<sqlite3_column_count(statement)).map { col in sqlite3_column_text(statement, col).map { String(cString: $0) } ?? "" })
        }
        return rows
    }
    private func scalar(_ sql: String, bindings: [String] = []) throws -> String? { try query(sql, bindings: bindings).first?.first }
    private func save<T: Encodable>(_ value: T, id: String, date: Date, table: String) throws {
        try requireWritable()
        let json = String(decoding: try JSONEncoder.stable.encode(value), as: UTF8.self)
        _ = try query("INSERT OR REPLACE INTO \(table) (id,timestamp,json) VALUES (?,?,?)", bindings: [id, String(date.timeIntervalSince1970), json])
    }
    private func read<T: Decodable>(_ type: T.Type, table: String, limit: Int? = nil) throws -> [T] {
        let clause = limit.map { " LIMIT \(max(1, $0))" } ?? ""
        return try query("SELECT json FROM \(table) ORDER BY timestamp DESC, id" + clause).map { try JSONDecoder.stored.decode(type, from: Data($0[0].utf8)) }
    }
    public func events(limit: Int = 200) throws -> [EvidenceEvent] { lock.lock(); defer { lock.unlock() }; return try read(EvidenceEvent.self, table: "events", limit: limit) }
    /// Query the selected time window directly, not just the most recent events.
    /// Results are bounded independently; saturation is visible to the caller.
    public func evidence(in interval: DateInterval, limit: Int = 200) throws -> EvidenceWindow {
        lock.lock(); defer { lock.unlock() }
        let bound = max(1, min(200, limit))
        func rows(_ table: String) throws -> [[String]] {
            try query("SELECT json FROM \(table) WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp DESC, id LIMIT ?",
                      bindings: [String(interval.start.timeIntervalSince1970), String(interval.end.timeIntervalSince1970), String(bound + 1)])
        }
        let events = try rows("events"), findings = try rows("findings")
        return EvidenceWindow(events: try events.prefix(bound).map { try JSONDecoder.stored.decode(EvidenceEvent.self, from: Data($0[0].utf8)) },
                              findings: try findings.prefix(bound).map { try JSONDecoder.stored.decode(Finding.self, from: Data($0[0].utf8)) },
                              eventsTruncated: events.count > bound, findingsTruncated: findings.count > bound)
    }
    public func findings() throws -> [Finding] { lock.lock(); defer { lock.unlock() }; return try read(Finding.self, table: "findings") }
    public func inventory() throws -> [InventoryRecord] { lock.lock(); defer { lock.unlock() }; return try read(InventoryRecord.self, table: "inventory") }
    public func sensors() throws -> [SensorHealth] { lock.lock(); defer { lock.unlock() }; return try read(SensorHealth.self, table: "sensors").sorted { $0.id < $1.id } }
    public func gaps() throws -> [CoverageGap] { lock.lock(); defer { lock.unlock() }; return try read(CoverageGap.self, table: "gaps") }
    public func event(id: String) throws -> EvidenceEvent? {
        lock.lock(); defer { lock.unlock() }
        guard let json = try scalar("SELECT json FROM events WHERE id=?", bindings: [id]) else { return nil }
        return try JSONDecoder.stored.decode(EvidenceEvent.self, from: Data(json.utf8))
    }
    /// Exact observation lookup, independent of the recent-events display limit.
    public func latestEvent(collector: String, key: String) throws -> EvidenceEvent? {
        lock.lock(); defer { lock.unlock() }
        guard let json = try scalar("SELECT json FROM events WHERE json_extract(json, '$.sourceCollector')=? AND json_extract(json, '$.observation.key')=? ORDER BY timestamp DESC, id LIMIT 1", bindings: [collector, key]) else { return nil }
        return try JSONDecoder.stored.decode(EvidenceEvent.self, from: Data(json.utf8))
    }
    public func agentActivity(now: Date = Date()) throws -> AgentActivityView {
        lock.lock(); defer { lock.unlock() }
        guard try scalar("SELECT name FROM sqlite_master WHERE type='table' AND name='agent_receipts'") != nil else { return AgentActivityView() }
        let latest = try scalar("SELECT json FROM agent_receipts ORDER BY timestamp DESC LIMIT 1").map { try JSONDecoder.stored.decode(AgentReceipt.self, from: Data($0.utf8)) }
        let rows = try query("SELECT json FROM agent_receipts WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT 2049", bindings: [String(now.addingTimeInterval(-86400).timeIntervalSince1970)])
        let records = try rows.prefix(2048).map { try JSONDecoder.stored.decode(AgentReceipt.self, from: Data($0[0].utf8)) }
        return AgentActivityView(reports: records, latestReport: latest?.timestamp, truncated: rows.count > 2048, latestEvent: latest)
    }
    public func recordAgentReceipt(_ receipt: AgentReceipt) throws {
        lock.lock(); defer { lock.unlock() }
        try requireWritable(); try execute("BEGIN IMMEDIATE")
        do {
            if try scalar("SELECT id FROM agent_receipts WHERE id=?", bindings: [receipt.id]) == nil {
                try save(receipt, id: receipt.id, date: receipt.timestamp, table: "agent_receipts")
                let attributes = ["hookEvent": receipt.event, "tool": receipt.tool ?? "NOT APPLICABLE", "sessionHash": receipt.sessionHash, "provider": receipt.provider.rawValue, "agentIdentity": receipt.identity, "attribution": "Application hook report; not kernel attestation", "process": "UNKNOWN"]
                let limits = ["Same-user local hook reports can be forged or omitted; this is not tamper-proof attribution.", "Reports do not prove tool success, file modification, a process launch, network traffic, or approval granted. Hook delivery can miss events.", "Arguments, outputs, prompts, transcripts and document contents are not retained."]
                let observation = Observation(key: receipt.id, eventClass: .health, component: "\(receipt.label): \(receipt.event) \(receipt.tool ?? "")", attributes: attributes, limitations: limits, confidence: .moderate)
                var evidence = EvidenceEvent(timestamp: receipt.timestamp, sourceCollector: receipt.provider.rawValue + "-hooks", eventType: "REPORTED", observation: observation, currentState: attributes, baselineStatus: .unknown, evidence: ["Metadata received through the explicitly configured agent metadata adapter. Timestamp is receipt time."], limitations: limits)
                evidence.id = receipt.id
                try save(evidence, id: receipt.id, date: receipt.timestamp, table: "events")
            }
            try execute("COMMIT")
        } catch { try? execute("ROLLBACK"); throw error }
    }
    public func codexHooks(now: Date = Date()) throws -> AgentActivityView { try agentActivity(now: now) }
    public func recordCodexHook(_ receipt: AgentReceipt) throws { try recordAgentReceipt(receipt) }
    public func integrityCheck() throws -> String { lock.lock(); defer { lock.unlock() }; return try scalar("PRAGMA quick_check") ?? "UNKNOWN" }
    public func metadata(_ key: String) throws -> String? { lock.lock(); defer { lock.unlock() }; return try scalar("SELECT value FROM metadata WHERE key=?", bindings: [key]) }
    public func setMetadata(_ key: String, _ value: String) throws { lock.lock(); defer { lock.unlock() }; try requireWritable(); _ = try query("INSERT OR REPLACE INTO metadata VALUES (?,?)", bindings: [key, value]) }
    public func tripwireRules() throws -> [TripwireRule] {
        lock.lock(); defer { lock.unlock() }
        guard let value = try metadata("tripwire-rules-v1") else { return [] }
        guard value.utf8.count <= 1_048_576 else { throw TripWireError.message("Tripwire configuration exceeds its size limit") }
        let rules = try JSONDecoder.stored.decode([TripwireRule].self, from: Data(value.utf8))
        guard rules.count <= 128, Set(rules.map(\.id)).count == rules.count else { throw TripWireError.message("Invalid tripwire configuration") }
        return try rules.map { try $0.validated() }
    }
    public func saveTripwire(_ proposed: TripwireRule) throws {
        var rule = try proposed.validated()
        guard rule.platform == HostPlatform.current else { throw TripWireError.message("Edit this tripwire on its configured platform") }
        rule.revision = UUID().uuidString
        try changeTripwires(action: "SAVED", rule: rule) { rules in
            if let i = rules.firstIndex(where: { $0.id == rule.id }) { rules[i] = rule }
            else { guard rules.count < 128 else { throw TripWireError.message("Up to 128 tripwires are supported") }; rules.append(rule) }
        }
    }
    public func deleteTripwire(id: String) throws {
        lock.lock(); defer { lock.unlock() }
        guard let rule = try tripwireRules().first(where: { $0.id == id }) else { throw TripWireError.message("Tripwire not found") }
        try changeTripwires(action: "DELETED", rule: rule) { $0.removeAll { $0.id == id } }
    }
    private func changeTripwires(action: String, rule: TripwireRule, change: (inout [TripwireRule]) throws -> Void) throws {
        lock.lock(); defer { lock.unlock() }
        try requireWritable(); try execute("BEGIN IMMEDIATE")
        do {
            var rules = try tripwireRules()
            let audited = action == "DELETED" ? rules.first(where: { $0.id == rule.id }) : rule
            guard let audited else { throw TripWireError.message("Tripwire no longer exists") }
            try change(&rules)
            try setMetadata("tripwire-rules-v1", String(decoding: try JSONEncoder.stable.encode(rules), as: UTF8.self))
            let attrs = ["ruleID": audited.id, "name": audited.name, "path": audited.path, "kind": audited.kind.rawValue, "enabled": String(audited.enabled), "revision": audited.revision]
            let observation = Observation(key: audited.id, eventClass: .configuration, component: audited.name, attributes: attrs)
            let event = EvidenceEvent(timestamp: Date(), sourceCollector: "tripwire-configuration", eventType: action, observation: observation, currentState: action == "DELETED" ? nil : attrs, baselineStatus: .unknown,
                evidence: ["Explicit local configuration change. No target was opened or modified. Rules apply to future observed snapshots; this is not a detection."], limitations: ["Rules alert on supported evidence and do not block access."])
            try save(event, id: event.id, date: event.timestamp, table: "events")
            try execute("COMMIT")
        } catch { try? execute("ROLLBACK"); throw error }
    }
    public func saveHealth(_ health: SensorHealth) throws { lock.lock(); defer { lock.unlock() }; try save(health, id: health.id, date: health.lastHeartbeat ?? Date(), table: "sensors") }
    public func recordGap(_ gap: CoverageGap) throws { lock.lock(); defer { lock.unlock() }; try save(gap, id: gap.id, date: gap.start, table: "gaps") }
    public func closeGaps(collector: String, at date: Date) throws {
        lock.lock(); defer { lock.unlock() }
        for var gap in try gaps() where gap.collector == collector && gap.end == nil {
            gap.end = date
            try save(gap, id: gap.id, date: gap.start, table: "gaps")
        }
    }
    public func approve(key: String, expectedFingerprint: String) throws {
        lock.lock(); defer { lock.unlock() }
        try requireWritable(); try execute("BEGIN IMMEDIATE")
        do {
            guard var record = try inventory().first(where: { $0.id == key && $0.present }) else { throw TripWireError.message("Current inventory key not found") }
            guard record.observation.fingerprint == expectedFingerprint else { throw TripWireError.message("Observation changed since review; inspect and approve its new fingerprint explicitly") }
            record.approvedFingerprint = expectedFingerprint; record.baselineStatus = .userApproved
            try save(record, id: key, date: record.lastSeen, table: "inventory")
            let event = EvidenceEvent(timestamp: Date(), sourceCollector: "user", eventType: "APPROVAL", observation: record.observation, currentState: record.observation.attributes, baselineState: record.baselineAttributes, baselineStatus: .userApproved, evidence: ["Explicit user approval of fingerprint \(expectedFingerprint); original baseline retained."])
            try save(event, id: event.id, date: event.timestamp, table: "events")
            try execute("COMMIT")
        } catch { try? execute("ROLLBACK"); throw error }
    }
    @discardableResult public func ingest(_ snapshot: CollectorSnapshot) throws -> [EvidenceEvent] {
        lock.lock(); defer { lock.unlock() }
        try requireWritable(); try execute("BEGIN IMMEDIATE")
        do {
            let collector = snapshot.descriptor.id
            let established = try metadata("baseline:\(collector)") != nil
            let scopeID = Digest.sha256(Data((snapshot.descriptor.source + "\n" + snapshot.descriptor.monitors).utf8))
            let usable = [.active, .degraded].contains(snapshot.state) && [.available, .limited].contains(snapshot.visibility)
            let scopeUnchanged = try sensors().first { $0.id == collector }.map { $0.descriptor.monitors == snapshot.descriptor.monitors && $0.descriptor.source == snapshot.descriptor.source } ?? true
            let establishing = !established && snapshot.complete && usable
            let existing = try inventory().filter { $0.collector == collector }
            var old = Dictionary(uniqueKeysWithValues: existing.map { ($0.observation.key, $0) })
            var emitted: [EvidenceEvent] = []
            var seen = Set<String>()
            for observation in snapshot.observations {
                guard seen.insert(observation.key).inserted else { continue }
                let prior = old.removeValue(forKey: observation.key)
                let baseline = establishing ? observation.attributes : prior?.baselineAttributes
                let status: BaselineStatus = !established && !establishing ? .unknown : BaselineEngine.status(current: observation, baseline: baseline, approvedFingerprint: prior?.approvedFingerprint)
                // A later complete file snapshot can establish a baseline without
                // repeating an already-recorded open-file observation/finding.
                let repeatedFile = observation.eventClass == .file && prior?.observation.attributes == observation.attributes
                let type = establishing && !repeatedFile ? "INITIAL" : prior == nil || prior?.present == false ? "NEW" : prior?.observation.attributes != observation.attributes ? "CHANGED" : "KNOWN"
                let record = InventoryRecord(id: collector + ":" + observation.key, collector: collector, observation: observation, firstSeen: prior?.firstSeen ?? snapshot.timestamp, lastSeen: snapshot.timestamp, observationCount: (prior?.observationCount ?? 0) + 1, present: true, baselineStatus: status, baselineAttributes: baseline, approvedFingerprint: prior?.approvedFingerprint, scopeID: scopeID)
                try save(record, id: record.id, date: record.lastSeen, table: "inventory")
                if type != "KNOWN" {
                    let event = EvidenceEvent(timestamp: snapshot.timestamp, sourceCollector: collector, eventType: type, observation: observation, previousState: prior?.present == true ? prior?.observation.attributes : nil, currentState: observation.attributes, baselineState: baseline, baselineStatus: status, evidence: ["Source: \(snapshot.descriptor.source)", "Inventory observation at \(TimeText.iso(snapshot.timestamp))"], limitations: snapshot.descriptor.limitations + (usable && snapshot.complete ? [] : ["Source result was partial or failed: " + snapshot.detail]))
                    emitted.append(event)
                }
            }
            // A failed/partial snapshot must NEVER create absence/removal evidence.
            if snapshot.complete && snapshot.absenceReliable && usable && scopeUnchanged && established {
                for var prior in old.values where prior.present && prior.scopeID == scopeID {
                    prior.present = false; prior.baselineStatus = .changed
                    try save(prior, id: prior.id, date: snapshot.timestamp, table: "inventory")
                    emitted.append(EvidenceEvent(timestamp: snapshot.timestamp, sourceCollector: collector, eventType: "REMOVED", observation: prior.observation, previousState: prior.observation.attributes, currentState: nil, baselineState: prior.baselineAttributes, baselineStatus: .changed, evidence: ["Absent from a successful inventory of the declared scope."], limitations: snapshot.descriptor.limitations + (usable && snapshot.complete ? [] : ["Source result was partial or failed: " + snapshot.detail])))
                }
            }
            if establishing { try setMetadata("baseline:\(collector)", TimeText.iso(snapshot.timestamp)) }
            for event in emitted {
                try save(event, id: event.id, date: event.timestamp, table: "events")
                if let finding = FindingEngine.make(event) { try save(finding, id: finding.id, date: finding.timestamp, table: "findings") }
            }
            // Evaluate fresh rows even when baseline metadata is unchanged. Saving
            // a rule never turns an old inventory record into a new observation.
            for match in TripwireMatcher.matches(snapshot, rules: try tripwireRules()) {
                guard try metadata(match.key) == nil else { continue }
                let event = EvidenceEvent(timestamp: snapshot.timestamp, sourceCollector: collector, eventType: "TRIPWIRE_MATCH", observation: match.observation,
                    currentState: match.observation.attributes, baselineStatus: .unknown,
                    evidence: ["User rule: \(match.rule.name) [\(match.rule.id)]", "Rule target: \(match.rule.path)", match.association, "Observed during this source snapshot; not a retroactive inventory match."],
                    limitations: snapshot.descriptor.limitations + TripwireMatcher.limitations + (snapshot.complete ? [] : ["Partial source: " + snapshot.detail]), severity: .elevated)
                let finding = match.finding(event: event)
                try save(event, id: event.id, date: event.timestamp, table: "events")
                try save(finding, id: finding.id, date: finding.timestamp, table: "findings")
                try setMetadata(match.key, finding.id); emitted.append(event)
            }
            let priorHealth = try sensors().first { $0.id == collector }
            let successful = usable && (snapshot.complete || !snapshot.observations.isEmpty)
            let reportedState: SensorState = !successful && [.active, .degraded].contains(snapshot.state) ? .error : snapshot.state
            let health = SensorHealth(descriptor: snapshot.descriptor, state: reportedState, visibility: !successful && [.available, .limited].contains(snapshot.visibility) ? .unknown : snapshot.visibility, initialized: successful, lastHeartbeat: snapshot.timestamp, lastSuccess: successful ? snapshot.timestamp : priorHealth?.lastSuccess, lastEvent: emitted.last?.timestamp ?? priorHealth?.lastEvent, detail: snapshot.detail)
            try saveHealth(health)
            if !scopeUnchanged { try recordGap(CoverageGap(collector: collector, start: priorHealth?.lastHeartbeat ?? snapshot.timestamp, end: snapshot.timestamp, reason: "Collector source/scope changed; absence inference suppressed for this transition")) }
            if !successful, priorHealth?.state != reportedState { try recordGap(CoverageGap(collector: collector, start: priorHealth?.lastSuccess ?? snapshot.timestamp, reason: snapshot.detail)) }
            if successful {
                for var gap in try gaps() where gap.collector == collector && gap.end == nil { gap.end = snapshot.timestamp; try save(gap, id: gap.id, date: gap.start, table: "gaps") }
            }
            try execute("COMMIT")
            return emitted
        } catch { try? execute("ROLLBACK"); throw error }
    }
    public func correlateRecent() throws {
        lock.lock(); defer { lock.unlock() }
        let existing = Set(try findings().filter { $0.ruleID == "persistence-process-network-v1" }.map { $0.eventIDs.sorted().joined(separator: ":") })
        for finding in CorrelationEngine.correlate(try events(limit: 2000)) where !existing.contains(finding.eventIDs.sorted().joined(separator: ":")) {
            try save(finding, id: finding.id, date: finding.timestamp, table: "findings")
        }
    }
}
