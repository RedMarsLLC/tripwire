#if os(macOS)
import Foundation
import Darwin
import EndpointSecurity
import TripWireCore

/// Explicit foreground diagnostic input, not a service or a native ES deployment.
/// Only allowlisted open-event metadata is decoded; raw input is never persisted.
public struct OpenEventRecord: Decodable {
    public struct Token: Decodable { public let pid: Int32; public let pidversion: UInt32; public let ruid: UInt32 }
    struct File: Decodable { let path: String; let path_truncated: Bool; let stat: Stat? }
    struct Stat: Decodable { let st_mode: UInt16 }
    struct Process: Decodable {
        let audit_token: Token; let responsible_audit_token: Token?; let parent_audit_token: Token?
        let executable: File; let ppid: Int32; let start_time: String
    }
    struct Open: Decodable { let file: File; let fflag: Int32 }
    struct Event: Decodable { let open: Open }
    let schema_version: Int; let version: UInt32; let event_type: UInt32
    let global_seq_num: UInt64?; let seq_num: UInt64?; let time: String
    let process: Process; let event: Event
    public static func decode(_ data: Data) throws -> Self {
        guard data.count <= 262_144 else { throw TripWireError.message("Open event exceeds the metadata limit") }
        let row = try JSONDecoder().decode(Self.self, from: data)
        guard row.schema_version == 1, row.event_type == ES_EVENT_TYPE_NOTIFY_OPEN.rawValue,
              !row.event.open.file.path_truncated, !row.process.executable.path_truncated,
              TripwirePath.normalize(row.event.open.file.path, platform: .macOS) != nil,
              TripwirePath.normalize(row.process.executable.path, platform: .macOS) != nil,
              row.process.audit_token.pid > 0, row.process.audit_token.pidversion > 0,
              timestamp(row.time) != nil, timestamp(row.process.start_time) != nil else {
            throw TripWireError.message("Unsupported, incomplete or truncated open-event metadata")
        }
        return row
    }
    static func timestamp(_ value: String) -> Date? {
        let format = ISO8601DateFormatter(); format.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = format.date(from: value) { return date }
        format.formatOptions = [.withInternetDateTime]; return format.date(from: value)
    }
    public func observation(session: String, since: Date, now: Date = Date(), uid: UInt32 = getuid(), rules: [TripwireRule],
                            associate: (Token) -> String?) -> Observation? {
        guard let stamp = Self.timestamp(time), stamp >= since, (-1...10).contains(now.timeIntervalSince(stamp)),
              process.audit_token.ruid == uid, let launched = Self.timestamp(process.start_time), launched <= stamp,
              let mode = event.open.file.stat?.st_mode, [UInt16(S_IFREG), UInt16(S_IFDIR)].contains(mode & UInt16(S_IFMT)),
              rules.contains(where: { $0.enabled && $0.platform == .macOS && TripwirePath.matches(event.open.file.path, rule: $0) }) else { return nil }
        // The responsible audit token survives a short-lived tool's exit. Validate
        // its PID version against the live recognized app; a PID alone is unsafe.
        var app: String?, basis = ""
        if let value = associate(process.audit_token) { app = value; basis = "Opening process audit identity matches a recognized AI app" }
        else if let token = process.responsible_audit_token, token.ruid == uid, let value = associate(token) {
            app = value; basis = "OS-reported responsible process audit identity matches a recognized AI app"
        } else if let token = process.parent_audit_token, token.ruid == uid, let value = associate(token) {
            app = value; basis = "OS-reported immediate parent audit identity matches a recognized AI app"
        }
        guard let app else { return nil }
        let sequence = global_seq_num.map(String.init) ?? seq_num.map(String.init) ?? time
        let id = Digest.sha256(Data("\(session):\(sequence):\(time):\(process.audit_token.pid):\(process.audit_token.pidversion):\(event.open.file.path)".utf8))
        let flags = UInt32(bitPattern: event.open.fflag)
        let openMode = flags & UInt32(O_EVTONLY) != 0 ? "Event-only" : flags & 3 == 1 ? "Read-capable" : flags & 3 == 2 ? "Write-capable" : flags & 3 == 3 ? "Read/write-capable" : "Unknown capability"
        let attributes = ["path": event.open.file.path, "pid": String(process.audit_token.pid), "executable": process.executable.path,
            "associatedApp": app, "associationBasis": basis, "openMode": openMode, "accessEventID": id,
            "objectType": mode & UInt16(S_IFMT) == UInt16(S_IFDIR) ? "Directory" : "Regular file", "eventTime": time,
            "pidVersion": String(process.audit_token.pidversion)]
        return Observation(key: id, eventClass: .file, component: event.open.file.path, attributes: attributes,
            process: ProcessIdentity(pid: process.audit_token.pid, parentPID: process.ppid, uid: uid, executablePath: process.executable.path, launchTime: launched),
            limitations: OpenEventBridge.limits, confidence: .moderate)
    }
}

public final class OpenEventBridge {
    public static let id = "file-open-events"
    public static let limits = [
        "Foreground diagnostic eslogger bridge, schema v1 only; Apple does not promise this diagnostic format's stability. This is not a deployed native Endpoint Security client.",
        "Only matching configured paths and recognized same-user AI responsible/parent audit identities are retained. Unrecognized, detached or unattributable accesses may be missed.",
        "An open notification establishes a reported open, not bytes read/written, user authorization or malicious intent. Descriptor inheritance and responsibility are not an AI instruction.",
        "Standard input is not authenticated; same-user reports can be forged. eslogger suppresses its own process group. Loss remains unknown when sequences are unavailable.",
        "No target contents, process arguments, environment values or raw event payloads are retained. Path aliases can evade lexical rules."
    ]
    public static let descriptor = SensorDescriptor(id, "File-open event bridge", source: "Explicit eslogger NOTIFY_OPEN JSONL input",
        monitors: "Reported file/directory opens at enabled tripwire paths, associated by validated responsible/parent audit identities",
        permissions: ["User-run eslogger requires administrator authorization and Full Disk Access for its responsible terminal"], limitations: limits)
    private let store: EventStore
    private let started = Date(), session = UUID().uuidString
    private var sequence = SequenceLossTracker()
    private var lastEvent: Date?, lastValid: Date?, lastHealth = Date.distantPast
    private var apps: [AIApplication] = [], rules: [TripwireRule] = []
    private var received = 0, retained = 0, invalid = 0, reportedInvalid = 0
    public init(store: EventStore) { self.store = store }
    public func refresh() async throws {
        apps = await AIAppResourceSampler.applications(); rules = try store.tripwireRules()
        try heartbeat()
    }
    public func consume(_ data: Data) throws {
        let row: OpenEventRecord
        do { row = try OpenEventRecord.decode(data) }
        catch { invalid += 1; return }
        guard let stamp = OpenEventRecord.timestamp(row.time), stamp >= started, (-1...10).contains(Date().timeIntervalSince(stamp)) else { invalid += 1; return }
        received += 1; lastValid = Date()
        if var gap = sequence.observe(version: row.version, type: row.event_type, sequence: row.seq_num, globalSequence: row.global_seq_num, at: Date()) {
            gap.collector = Self.id; try store.recordGap(gap)
        }
        guard let observation = row.observation(session: session, since: started, rules: rules, associate: { token in
            guard token.ruid == getuid(), let metadata = AIAppResourceSampler.metadata(token.pid) else { return nil }
            guard Self.matchesLiveAuditToken(token),
                  let after = AIAppResourceSampler.metadata(token.pid), after.started == metadata.started, after.path == metadata.path,
                  let app = self.apps.first(where: { $0.pid == token.pid && metadata.path.hasPrefix($0.bundlePath + "/") }) else { return nil }
            return app.name
        }) else { return }
        try store.ingest(CollectorSnapshot(descriptor: Self.descriptor, timestamp: stamp, observations: [observation], complete: false, absenceReliable: false,
            state: .degraded, visibility: .limited, detail: "One scoped open-event notification; not a complete inventory or proof of a read/write."))
        retained += 1; lastEvent = stamp
    }
    private static func matchesLiveAuditToken(_ token: OpenEventRecord.Token) -> Bool {
        var port: mach_port_t = 0
        guard task_name_for_pid(mach_task_self_, token.pid, &port) == KERN_SUCCESS else { return false }
        defer { mach_port_deallocate(mach_task_self_, port) }
        var identity = audit_token_t()
        var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<integer_t>.size)
        let result = withUnsafeMutablePointer(to: &identity) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(port, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
            }
        }
        return result == KERN_SUCCESS && identity.val.5 == UInt32(token.pid) && identity.val.7 == token.pidversion && identity.val.3 == token.ruid
    }
    public func heartbeat() throws {
        let now = Date(); guard now.timeIntervalSince(lastHealth) >= 2 else { return }; lastHealth = now
        if invalid > reportedInvalid {
            try store.recordGap(CoverageGap(collector: Self.id, start: now, end: now, reason: "\(invalid - reportedInvalid) unsupported, stale or incomplete input records rejected. Raw payload discarded; missed accesses UNKNOWN."))
            reportedInvalid = invalid
        }
        let current = lastValid.map { now.timeIntervalSince($0) < 10 } ?? false
        try store.saveHealth(SensorHealth(descriptor: Self.descriptor, state: current ? .degraded : .error, visibility: current ? .limited : .unknown,
            initialized: lastValid != nil, lastHeartbeat: now, lastSuccess: lastValid, lastEvent: lastEvent,
            detail: "\(received) valid open reports received; \(retained) scoped AI-associated records retained; \(invalid) invalid records. \(current ? "Event stream reporting with the stated limits." : "No recent valid input: verify eslogger authorization and the foreground pipe. Silence cannot establish coverage.")"))
    }
    public func stop() throws {
        try store.saveHealth(SensorHealth(descriptor: Self.descriptor, state: .stopped, visibility: .unknown, initialized: lastValid != nil,
            lastHeartbeat: Date(), lastSuccess: lastValid, lastEvent: lastEvent, detail: "Foreground event bridge ended; file-open event coverage is off."))
        try store.recordGap(CoverageGap(collector: Self.id, start: Date(), reason: "File-open event bridge stopped; brief access may be missed by snapshots."))
    }
}
#endif
