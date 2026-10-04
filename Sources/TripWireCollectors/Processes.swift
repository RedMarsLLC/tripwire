import Foundation
import Darwin
import TripWireCore

public enum ProcessParser {
    public static func parse(_ text: String) -> (processes: [ProcessIdentity], invalid: Int) {
        let regex = try! NSRegularExpression(pattern: #"^\s*(\d+)\s+(\d+)\s+(\d+)\s+([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(.+)$"#)
        let formatter = DateFormatter(); formatter.locale = Locale(identifier: "en_US_POSIX"); formatter.dateFormat = "EEE MMM d HH:mm:ss yyyy"
        var processes: [ProcessIdentity] = [], invalid = 0
        for line in text.split(separator: "\n").map(String.init) {
            guard let m = regex.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)) else { invalid += 1; continue }
            func value(_ i: Int) -> String { String(line[Range(m.range(at: i), in: line)!]) }
            let path = value(5)
            processes.append(ProcessIdentity(pid: Int32(value(1)), parentPID: Int32(value(2)), uid: UInt32(value(3)), executablePath: path.hasPrefix("/") ? path : nil, launchTime: formatter.date(from: value(4))))
        }
        return (processes, invalid)
    }
    public static func snapshot() -> (processes: [ProcessIdentity], valid: Bool) {
        let command = ReadCommand.run("/bin/ps", ["-ww", "-axo", "pid=,ppid=,uid=,lstart=,comm="])
        let parsed = parse(command.text)
        return (parsed.processes, command.successful && command.error.isEmpty && parsed.invalid == 0 && !parsed.processes.isEmpty)
    }
}
public struct ProcessCollector: Collector {
    public let descriptor = SensorDescriptor("processes", "Process snapshots", source: "ps(1), bounded Security signing metadata", monitors: "Running processes visible to this user at sample time; PID, parent PID, UID, start time and executable when available", limitations: ["Not an execution event stream. Short-lived processes may be missed.", "Start time has one-second precision; PID reuse within that interval is ambiguous.", "Executable paths/signing metadata may be unavailable or race process exit/replacement.", "Arguments and environment variables are not collected.", "Signing lookups have a two-second total wait budget and two outstanding workers; unavailable metadata remains unknown."])
    public init() {}
    public func collect() async -> CollectorSnapshot {
        let result = ProcessParser.snapshot()
        var cache: [String: ProcessIdentity] = [:]
        let deadline = ProcessInfo.processInfo.systemUptime + 2
        let observations = result.processes.map { p -> Observation in
            var process = p
            if let path = p.executablePath {
                if cache[path] == nil { cache[path] = BoundedSignatureLookup.shared.identity(path, timeout: min(0.2, deadline - ProcessInfo.processInfo.systemUptime)) }
                process.teamID = cache[path]?.teamID; process.bundleID = cache[path]?.bundleID; process.signingIdentity = cache[path]?.signingIdentity; process.signatureStatus = cache[path]?.signatureStatus
            }
            let path = process.executablePath ?? "UNKNOWN"
            let key = process.instanceKey ?? "unknown:\(process.pid ?? -1)"
            return Observation(key: key, eventClass: .process, component: path, attributes: ["collectorUID": String(getuid()), "executable": path, "uid": process.uid.map(String.init) ?? "UNKNOWN", "teamID": process.teamID ?? "UNKNOWN", "signature": process.signatureStatus ?? "UNKNOWN"], process: process, limitations: descriptor.limitations, confidence: .moderate)
        }
        return CollectorSnapshot(descriptor: descriptor, observations: observations, complete: result.valid, state: result.valid ? .degraded : .error, detail: result.valid ? "Periodic process inventory; execution continuity NOT OBSERVABLE" : "Process source failed or unrecognized rows; no removals inferred")
    }
}
