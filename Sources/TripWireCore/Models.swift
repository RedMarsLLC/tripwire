import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import CTripWirePlatform
#endif

public enum SensorState: String, Codable, CaseIterable { case active = "ACTIVE", degraded = "DEGRADED", permissionMissing = "PERMISSION MISSING", unsupported = "UNSUPPORTED", error = "ERROR", stopped = "STOPPED", dataLossDetected = "DATA LOSS DETECTED" }
public enum Visibility: String, Codable { case available = "OBSERVABLE", limited = "LIMITED", unknown = "UNKNOWN", unavailable = "UNAVAILABLE", notObservable = "NOT OBSERVABLE" }
public enum BaselineStatus: String, Codable { case known = "KNOWN", new = "NEW", changed = "CHANGED", userApproved = "USER APPROVED", systemExpected = "SYSTEM EXPECTED", unknown = "UNKNOWN" }
public enum EventClass: String, Codable { case file = "FILE", process = "EXEC", network = "NET", listener = "PORT", application = "APP", persistence = "PERSIST", extensions = "EXT", hardware = "HW", privacy = "PRIV", configuration = "CONFIG", endpointSecurity = "ES", health = "HEALTH", canary = "CANARY" }
public enum Confidence: String, Codable { case high = "HIGH", moderate = "MODERATE", low = "LOW", unknown = "UNKNOWN" }
public enum Severity: String, Codable { case informational = "INFORMATIONAL", notice = "NOTICE", elevated = "ELEVATED" }

public struct ProcessIdentity: Codable, Equatable {
    public var pid: Int32?
    public var parentPID: Int32?
    public var uid: UInt32?
    /// Windows account SID; a POSIX UID is not synthesized from a SID.
    public var accountID: String?
    public var executablePath: String?
    public var launchTime: Date?
    public var bundleID: String?
    public var teamID: String?
    public var signingIdentity: String?
    public var signatureStatus: String?
    public var hash: String?
    public init(pid: Int32? = nil, parentPID: Int32? = nil, uid: UInt32? = nil, accountID: String? = nil, executablePath: String? = nil, launchTime: Date? = nil, bundleID: String? = nil, teamID: String? = nil, signingIdentity: String? = nil, signatureStatus: String? = nil, hash: String? = nil) {
        self.pid = pid; self.parentPID = parentPID; self.uid = uid; self.accountID = accountID; self.executablePath = executablePath; self.launchTime = launchTime; self.bundleID = bundleID; self.teamID = teamID; self.signingIdentity = signingIdentity; self.signatureStatus = signatureStatus; self.hash = hash
    }
    // A PID alone is never a correlation identity: it can be reused.
    public var instanceKey: String? {
        guard let pid, let launchTime, let executablePath else { return nil }
        return "\(pid):\(launchTime.timeIntervalSince1970):\(executablePath)"
    }
}

public struct Observation: Codable, Equatable, Identifiable {
    public var id: String { key }
    public var key: String
    public var eventClass: EventClass
    public var component: String
    public var attributes: [String: String]
    public var process: ProcessIdentity?
    public var limitations: [String]
    public var confidence: Confidence
    public init(key: String, eventClass: EventClass, component: String, attributes: [String: String], process: ProcessIdentity? = nil, limitations: [String] = [], confidence: Confidence = .high) {
        self.key = key; self.eventClass = eventClass; self.component = component; self.attributes = attributes; self.process = process; self.limitations = limitations; self.confidence = confidence
    }
    public var fingerprint: String { Digest.sha256((try? JSONEncoder.stable.encode(attributes)) ?? Data()) }
}

public struct EvidenceEvent: Codable, Identifiable {
    public var id: String
    public var timestamp: Date
    public var sourceCollector: String
    public var eventType: String
    public var observation: Observation
    public var previousState: [String: String]?
    public var currentState: [String: String]?
    public var baselineState: [String: String]?
    public var baselineStatus: BaselineStatus
    public var evidence: [String]
    public var limitations: [String]
    public var severity: Severity
    public var rawMetadata: [String: String]
    public init(timestamp: Date, sourceCollector: String, eventType: String, observation: Observation, previousState: [String: String]? = nil, currentState: [String: String]?, baselineState: [String: String]? = nil, baselineStatus: BaselineStatus, evidence: [String] = [], limitations: [String] = [], severity: Severity = .informational) {
        id = UUID().uuidString; self.timestamp = timestamp; self.sourceCollector = sourceCollector; self.eventType = eventType; self.observation = observation; self.previousState = previousState; self.currentState = currentState; self.baselineState = baselineState; self.baselineStatus = baselineStatus; self.evidence = evidence; self.limitations = limitations; self.severity = severity; rawMetadata = ["schemaVersion": "1", "collectorBuild": "0.1.0", "operatingSystem": ProcessInfo.processInfo.operatingSystemVersionString]
    }
}

public struct SensorDescriptor: Codable, Identifiable {
    public var id: String
    public var name: String
    public var source: String
    public var monitors: String
    public var permissions: [String]
    public var limitations: [String]
    public init(_ id: String, _ name: String, source: String, monitors: String, permissions: [String] = [], limitations: [String] = []) {
        self.id = id; self.name = name; self.source = source; self.monitors = monitors; self.permissions = permissions; self.limitations = limitations
    }
}
public struct SensorHealth: Codable, Identifiable {
    public var id: String { descriptor.id }
    public var descriptor: SensorDescriptor
    public var state: SensorState
    public var visibility: Visibility
    public var initialized: Bool
    public var lastHeartbeat: Date?
    public var lastSuccess: Date?
    public var lastEvent: Date?
    public var detail: String
    public var droppedEvents: UInt64?
    public var queueBacklog: Int?
    public var lastSequence: UInt64?
    public init(descriptor: SensorDescriptor, state: SensorState = .stopped, visibility: Visibility = .unknown, initialized: Bool = false, lastHeartbeat: Date? = nil, lastSuccess: Date? = nil, lastEvent: Date? = nil, detail: String = "Not started", droppedEvents: UInt64? = nil, queueBacklog: Int? = nil, lastSequence: UInt64? = nil) {
        self.descriptor = descriptor; self.state = state; self.visibility = visibility; self.initialized = initialized; self.lastHeartbeat = lastHeartbeat; self.lastSuccess = lastSuccess; self.lastEvent = lastEvent; self.detail = detail; self.droppedEvents = droppedEvents; self.queueBacklog = queueBacklog; self.lastSequence = lastSequence
    }
    public func effective(at date: Date = Date(), staleAfter: TimeInterval = 90) -> SensorHealth {
        var copy = self
        if [.active, .degraded].contains(state) {
            guard let lastHeartbeat else { copy.state = .stopped; copy.visibility = .unknown; copy.detail = "UNKNOWN: collector has no heartbeat"; return copy }
            if date.timeIntervalSince(lastHeartbeat) > staleAfter || lastHeartbeat.timeIntervalSince(date) > 5 {
                copy.state = .stopped; copy.visibility = .unknown; copy.detail = "STALE / CLOCK DISCONTINUITY: heartbeat \(TimeText.iso(lastHeartbeat)). Last reported: \(state.rawValue)."
            }
        }
        return copy
    }
}
public struct CollectorSnapshot {
    public var descriptor: SensorDescriptor
    public var timestamp: Date
    public var observations: [Observation]
    /// Complete only for the descriptor's declared inventory scope, never the entire host.
    public var complete: Bool
    public var absenceReliable: Bool
    public var state: SensorState
    public var visibility: Visibility
    public var detail: String
    public init(descriptor: SensorDescriptor, timestamp: Date = Date(), observations: [Observation] = [], complete: Bool = false, absenceReliable: Bool = true, state: SensorState = .degraded, visibility: Visibility = .limited, detail: String) {
        self.descriptor = descriptor; self.timestamp = timestamp; self.observations = observations; self.complete = complete; self.absenceReliable = absenceReliable; self.state = state; self.visibility = visibility; self.detail = detail
    }
}
public protocol Collector {
    var descriptor: SensorDescriptor { get }
    func collect() async -> CollectorSnapshot
}
public struct InventoryRecord: Codable, Identifiable {
    public var id: String
    public var collector: String
    public var observation: Observation
    public var firstSeen: Date
    public var lastSeen: Date
    public var observationCount: Int
    public var present: Bool
    public var baselineStatus: BaselineStatus
    public var baselineAttributes: [String: String]?
    public var approvedFingerprint: String?
    public var scopeID: String?
}
public struct CoverageGap: Codable, Identifiable {
    public var id = UUID().uuidString
    public var collector: String
    public var start: Date
    public var end: Date?
    public var reason: String
    public var lostCount: UInt64?
    public init(collector: String, start: Date, end: Date? = nil, reason: String, lostCount: UInt64? = nil) { self.collector = collector; self.start = start; self.end = end; self.reason = reason; self.lostCount = lostCount }
}
public struct Finding: Codable, Identifiable {
    public var id = UUID().uuidString
    public var timestamp: Date
    public var title: String
    public var whatHappened: String
    public var whyFlagged: String
    public var component: String
    public var eventIDs: [String]
    public var baselineDifference: String
    public var confidence: Confidence
    public var severity: Severity
    public var limitations: [String]
    public var suggestedInvestigation: [String]
    public var intent: String = "UNKNOWN"
    public var ruleID: String
}
public enum Digest {
    public static func sha256(_ data: Data) -> String {
        #if canImport(CryptoKit)
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        #else
        var digest = [UInt8](repeating: 0, count: 32)
        let result = data.withUnsafeBytes { tw_sha256($0.bindMemory(to: UInt8.self).baseAddress, $0.count, &digest) }
        precondition(result == 0, "System SHA-256 provider unavailable; refusing to fabricate evidence fingerprints")
        return digest.map { String(format: "%02x", $0) }.joined()
        #endif
    }
}
extension JSONEncoder {
    public static var stable: JSONEncoder { let e = JSONEncoder(); e.outputFormatting = [.sortedKeys]; e.dateEncodingStrategy = .millisecondsSince1970; return e }
}
extension JSONDecoder {
    public static var stored: JSONDecoder { let d = JSONDecoder(); d.dateDecodingStrategy = .millisecondsSince1970; return d }
}
public enum TimeText {
    public static func iso(_ d: Date?) -> String { d.map { ISO8601DateFormatter().string(from: $0) } ?? "UNKNOWN" }
}
public enum TripWireError: Error, CustomStringConvertible {
    case message(String)
    public var description: String { switch self { case .message(let s): return s } }
}
