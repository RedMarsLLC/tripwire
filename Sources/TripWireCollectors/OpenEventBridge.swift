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
    struct Target: Decodable { let target: File }
    struct Close: Decodable { let target: File; let modified: Bool }
    struct Rename: Decodable {
        struct NewPath: Decodable { let dir: File; let filename: String }
        struct Destination: Decodable { let existing_file: File?; let new_path: NewPath? }
        let source: File; let destination_type: UInt32; let destination: Destination
    }
    struct Event: Decodable { let open: Open?; let write: Target?; let close: Close?; let unlink: Target?; let rename: Rename? }
    let schema_version: Int; let version: UInt32; let event_type: UInt32
    let global_seq_num: UInt64?; let seq_num: UInt64?; let time: String
    let process: Process; let event: Event
    var operation: String {
        switch event_type {
        case ES_EVENT_TYPE_NOTIFY_OPEN.rawValue: return "Open reported (bytes read/written unknown)"
        case ES_EVENT_TYPE_NOTIFY_WRITE.rawValue: return "Write reported (contents not collected)"
        case ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue: return event.close?.modified == true ? "Close reported with modification" : "Close reported without modification"
        case ES_EVENT_TYPE_NOTIFY_UNLINK.rawValue: return "Unlink reported (removal of a directory entry, not proof of data erasure)"
        default: return "Rename reported"
        }
    }
    var action: String {
        switch event_type {
        case ES_EVENT_TYPE_NOTIFY_OPEN.rawValue: return "opening"
        case ES_EVENT_TYPE_NOTIFY_WRITE.rawValue: return "writing to"
        case ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue: return "closing after modification of"
        case ES_EVENT_TYPE_NOTIFY_UNLINK.rawValue: return "unlinking"
        default: return "renaming"
        }
    }
    private func targets() throws -> [(File, String)] {
        switch event_type {
        case ES_EVENT_TYPE_NOTIFY_OPEN.rawValue: if let value = event.open { return [(value.file, "target")] }
        case ES_EVENT_TYPE_NOTIFY_WRITE.rawValue: if let value = event.write { return [(value.target, "target")] }
        case ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue: if let value = event.close { return [(value.target, "target")] }
        case ES_EVENT_TYPE_NOTIFY_UNLINK.rawValue: if let value = event.unlink { return [(value.target, "target")] }
        case ES_EVENT_TYPE_NOTIFY_RENAME.rawValue:
            if let value = event.rename {
                if value.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE.rawValue, let target = value.destination.existing_file { return [(value.source, "source"), (target, "destination")] }
                if value.destination_type == ES_DESTINATION_TYPE_NEW_PATH.rawValue, let target = value.destination.new_path,
                   !target.dir.path_truncated, !target.filename.isEmpty, ![".", ".."].contains(target.filename), !target.filename.contains("/") {
                    return [(value.source, "source"), (File(path: target.dir.path + "/" + target.filename, path_truncated: false, stat: value.source.stat), "destination")]
                }
            }
        default: break
        }
        throw TripWireError.message("Unsupported or incomplete file-event metadata")
    }
    public static func decode(_ data: Data) throws -> Self {
        guard data.count <= 262_144 else { throw TripWireError.message("File event exceeds the metadata limit") }
        let row = try JSONDecoder().decode(Self.self, from: data)
        guard row.schema_version == 1, !row.process.executable.path_truncated,
              TripwirePath.normalize(row.process.executable.path, platform: .macOS) != nil,
              row.process.audit_token.pid > 0, row.process.audit_token.pidversion > 0,
              timestamp(row.time) != nil, timestamp(row.process.start_time) != nil,
              try row.targets().allSatisfy({ !$0.0.path_truncated && TripwirePath.normalize($0.0.path, platform: .macOS) != nil && $0.0.stat != nil }) else {
            throw TripWireError.message("Unsupported, incomplete or truncated file-event metadata")
        }
        return row
    }
    static func timestamp(_ value: String) -> Date? {
        // FormatStyle is a reusable value parser. Constructing ICU formatters for
        // every field on every system event can make the pipe fall behind.
        (try? Date.ISO8601FormatStyle(includingFractionalSeconds: true).parse(value)) ??
            (try? Date.ISO8601FormatStyle(includingFractionalSeconds: false).parse(value))
    }
    public func observation(session: String, since: Date, now: Date = Date(), uid: UInt32 = getuid(), rules: [TripwireRule],
                            associate: (Token) -> String?) -> Observation? {
        observations(session: session, since: since, now: now, uid: uid, rules: rules, associate: associate).first
    }
    public func observations(session: String, since: Date, now: Date = Date(), uid: UInt32 = getuid(), rules: [TripwireRule],
                             associate: (Token) -> String?, executable: (Token) -> String? = { _ in nil }) -> [Observation] {
        guard let stamp = Self.timestamp(time), stamp >= since, (-1...10).contains(now.timeIntervalSince(stamp)),
              process.audit_token.ruid == uid, let launched = Self.timestamp(process.start_time), launched <= stamp,
              let targets = try? targets() else { return [] }
        // Unmodified closes add no boundary action beyond their open; they still
        // count as valid feed input and participate in sequence-loss tracking.
        if event_type == ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue && event.close?.modified != true { return [] }
        let scoped = targets.filter { file, _ in
            guard let mode = file.stat?.st_mode, [UInt16(S_IFREG), UInt16(S_IFDIR)].contains(mode & UInt16(S_IFMT)) else { return false }
            return rules.contains { $0.enabled && $0.platform == .macOS && ($0.updatedAt == nil || stamp >= $0.updatedAt!) && TripwirePath.matches(file.path, rule: $0) }
        }
        guard !scoped.isEmpty else { return [] }
        // A responsible identity can survive the tool's exit. An AI association
        // requires a live validated PID version; account-wide rules do not.
        var app: String?, basis = ""
        if let value = associate(process.audit_token) { app = value; basis = "Acting process audit identity matches a recognized AI app" }
        else if let token = process.responsible_audit_token, token.ruid == uid, let value = associate(token) {
            app = value; basis = "OS-reported responsible process audit identity matches a recognized AI app"
        } else if let token = process.parent_audit_token, token.ruid == uid, let value = associate(token) {
            app = value; basis = "OS-reported immediate parent audit identity matches a recognized AI app"
        }
        var context = ["pid": String(process.audit_token.pid), "executable": process.executable.path, "collectorUID": String(uid),
            "operation": operation, "operationAction": action, "eventTime": time, "pidVersion": String(process.audit_token.pidversion)]
        if let app { context["associatedApp"] = app; context["associationBasis"] = basis }
        if let token = process.parent_audit_token, token.ruid == uid, token.pid == process.ppid { context["parentExecutable"] = executable(token) }
        if let token = process.responsible_audit_token, token.ruid == uid {
            context["responsiblePID"] = String(token.pid); context["responsiblePIDVersion"] = String(token.pidversion)
            context["responsibleExecutable"] = executable(token)
        }
        if let value = event.open, event_type == ES_EVENT_TYPE_NOTIFY_OPEN.rawValue {
            let flags = UInt32(bitPattern: value.fflag)
            context["openMode"] = flags & UInt32(O_EVTONLY) != 0 ? "Event-only" : flags & 3 == 1 ? "Read-capable" : flags & 3 == 2 ? "Write-capable" : flags & 3 == 3 ? "Read/write-capable" : "Unknown capability"
        }
        let sequence = global_seq_num.map(String.init) ?? seq_num.map(String.init) ?? time
        return scoped.compactMap { file, role in
            guard app != nil || rules.contains(where: { $0.enabled && $0.platform == .macOS && $0.effectiveScope == .currentUser && ($0.updatedAt == nil || stamp >= $0.updatedAt!) && TripwirePath.matches(file.path, rule: $0) }) else { return nil }
            let id = Digest.sha256(Data("\(session):\(sequence):\(time):\(event_type):\(process.audit_token.pid):\(process.audit_token.pidversion):\(role):\(file.path)".utf8))
            var attributes = context; attributes["path"] = file.path; attributes["pathRole"] = role; attributes["accessEventID"] = id
            attributes["objectType"] = file.stat!.st_mode & UInt16(S_IFMT) == UInt16(S_IFDIR) ? "Directory" : "Regular file"
            // Retain only paths inside enabled boundaries, even for a rename.
            return Observation(key: id, eventClass: .file, component: file.path, attributes: attributes,
                process: ProcessIdentity(pid: process.audit_token.pid, parentPID: process.ppid, uid: uid, executablePath: process.executable.path, launchTime: launched),
                limitations: OpenEventBridge.limits, confidence: .moderate)
        }
    }

}

public final class OpenEventBridge {
    public static let id = "file-open-events"
    public static let limits = [
        "Foreground diagnostic eslogger bridge, schema v1 only; Apple does not promise this diagnostic format's stability. This is not a deployed native Endpoint Security client.",
        "Only enabled boundary paths are retained. AI-only rules require recognized same-user audit identities; current-account rules also include unrecognized tools and manual apps. Other accounts remain outside scope.",
        "An open notification is not bytes read/written. Write, modified-close, rename and unlink reports identify their stated operation only; contents, input method, authorization and intent remain unknown.",
        "Standard input is not authenticated; same-user reports can be forged. eslogger suppresses its own process group. Loss remains unknown when sequences are unavailable.",
        "No target contents, process arguments, environment values or raw event payloads are retained. Path aliases can evade lexical rules."
    ]
    public static let descriptor = SensorDescriptor(id, "File activity event bridge", source: "Explicit eslogger open/write/close/rename/unlink JSONL input",
        monitors: "Reported file operations at enabled paths, scoped to the monitoring account or recognized AI identities",
        permissions: ["User-run eslogger requires administrator authorization and Full Disk Access for its responsible terminal"], limitations: limits)
    private let store: EventStore
    private let started = Date(), session = UUID().uuidString
    private var sequence = SequenceLossTracker()
    private var lastEvent: Date?, lastValid: Date?, lastHealth = Date.distantPast
    private var apps: [AIApplication] = [], rules: [TripwireRule] = []
    private var received = 0, retained = 0, invalid = 0, reportedInvalid = 0
    private var observedTypes = Set<UInt32>()
    private var rejectedFormat = 0, rejectedTime = 0
    private var latestInputAge: TimeInterval?
    public init(store: EventStore) { self.store = store }
    public func refresh() async throws {
        apps = await AIAppResourceSampler.applications(); rules = try store.tripwireRules()
        try heartbeat()
    }
    public func consume(_ data: Data) throws {
        let row: OpenEventRecord
        do { row = try OpenEventRecord.decode(data) }
        catch { invalid += 1; rejectedFormat += 1; return }
        guard let stamp = OpenEventRecord.timestamp(row.time) else { invalid += 1; rejectedFormat += 1; return }
        latestInputAge = Date().timeIntervalSince(stamp)
        guard stamp >= started, (-1...10).contains(latestInputAge!) else { invalid += 1; rejectedTime += 1; return }
        received += 1; lastValid = Date(); observedTypes.insert(row.event_type)
        if var gap = sequence.observe(version: row.version, type: row.event_type, sequence: row.seq_num, globalSequence: row.global_seq_num, at: Date()) {
            gap.collector = Self.id; try store.recordGap(gap)
        }
        let observations = row.observations(session: session, since: started, rules: rules, associate: { token in
            guard let path = Self.liveExecutable(token),
                  let app = self.apps.first(where: { $0.pid == token.pid && path.hasPrefix($0.bundlePath + "/") }) else { return nil }
            return app.name
        }, executable: Self.liveExecutable)
        guard !observations.isEmpty else { return }
        try store.ingest(CollectorSnapshot(descriptor: Self.descriptor, timestamp: stamp, observations: observations, complete: false, absenceReliable: false,
            state: .degraded, visibility: .limited, detail: "Scoped file-operation notification; not a complete inventory or an audit of input/contents."))
        retained += observations.count; lastEvent = stamp
    }
    private static func liveExecutable(_ token: OpenEventRecord.Token) -> String? {
        guard token.ruid == getuid(), let before = AIAppResourceSampler.metadata(token.pid), matchesLiveAuditToken(token),
              let after = AIAppResourceSampler.metadata(token.pid), before.started == after.started, before.path == after.path else { return nil }
        return after.path
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
            detail: "\(received) valid file reports received; \(retained) scoped records retained; \(invalid) rejected (\(rejectedFormat) format/metadata, \(rejectedTime) stale/time). Latest input age: \(latestInputAge.map { String(format: "%.2fs", $0) } ?? "unknown"). Observed event type IDs: \(observedTypes.sorted().map(String.init).joined(separator: ", ")). \(current ? "Event stream reporting with the stated limits. Subscribed event types are not verified by stdin; only observed types are known." : "No recent valid input: verify eslogger authorization and the foreground pipe. Silence cannot establish coverage.")"))
    }
    public func stop() throws {
        try store.saveHealth(SensorHealth(descriptor: Self.descriptor, state: .stopped, visibility: .unknown, initialized: lastValid != nil,
            lastHeartbeat: Date(), lastSuccess: lastValid, lastEvent: lastEvent, detail: "Foreground event bridge ended; file-open event coverage is off."))
        try store.recordGap(CoverageGap(collector: Self.id, start: Date(), reason: "File-open event bridge stopped; brief access may be missed by snapshots."))
    }
}
#endif
