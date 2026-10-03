#if os(Windows)
import Foundation
import CTripWirePlatform
import TripWireCore

enum WindowsSources {
    static func string<T>(_ field: T) -> String { withUnsafeBytes(of: field) { bytes in
        String(decoding: bytes.prefix(while: { $0 != 0 }), as: UTF8.self)
    } }
    static func processes() -> (identities: [ProcessIdentity], limited: Bool) {
        let count = 8192; let rows = UnsafeMutablePointer<TWProcess>.allocate(capacity: count)
        defer { rows.deallocate() }; var limited: Int32 = 0
        let result = tw_processes(rows, Int32(count), &limited)
        guard result >= 0 else { return ([], true) }
        let identities = (0..<Int(result)).map { i -> ProcessIdentity in
            let r = rows[i], path = string(r.path), sid = string(r.account)
            let start = r.started > 116444736000000000 ? Date(timeIntervalSince1970: Double(r.started - 116444736000000000) / 10_000_000) : nil
            return ProcessIdentity(pid: Int32(exactly: r.pid), parentPID: Int32(exactly: r.parent_pid), accountID: sid.isEmpty ? nil : sid,
                executablePath: path.isEmpty ? nil : path, launchTime: start, signatureStatus: "NOT OBSERVABLE — Authenticode adapter not implemented")
        }
        return (identities, limited != 0)
    }
}
public struct ProcessCollector: Collector {
    public let descriptor = SensorDescriptor("processes", "Process snapshots", source: "Windows Tool Help, QueryFullProcessImageName, GetProcessTimes and token SID",
        monitors: "Visible PID/parent PID, creation time, executable path and account SID",
        limitations: ["Polling misses brief processes; protected processes and inaccessible identities remain unknown.", "Parent PID alone is not a verified ancestry chain. Arguments, environment and memory contents are never read.", "Executable names are not AI or signer attestation."])
    public init() {}
    public func collect() async -> CollectorSnapshot {
        let result = WindowsSources.processes()
        let rows = result.identities.map { p in Observation(key: p.instanceKey ?? "unknown:\(p.pid ?? -1)", eventClass: .process,
            component: p.executablePath ?? "PID \(p.pid ?? -1) · executable unknown",
            attributes: ["executable": p.executablePath ?? "UNKNOWN", "accountSID": p.accountID ?? "UNKNOWN", "signature": p.signatureStatus ?? "UNKNOWN"], process: p, limitations: descriptor.limitations, confidence: .moderate) }
        return CollectorSnapshot(descriptor: descriptor, observations: rows, complete: !result.limited, absenceReliable: false,
            state: rows.isEmpty ? .error : .degraded, detail: "\(rows.count) visible process records; \(result.limited ? "protected, denied or bounded entries omitted/incomplete" : "snapshot only"). No exit or exhaustive-coverage inference.")
    }
}
public struct NetworkCollector: Collector {
    public let descriptor = SensorDescriptor("network", "Connections and listeners", source: "Windows IP Helper extended TCP/UDP owner-PID tables (IPv4/IPv6)", monitors: "Visible TCP socket states, UDP bindings and owner PIDs",
        limitations: ["Polling misses short-lived sockets; listening does not establish reachability.", "Owner PID is not a revalidated process instance or proof of AI causation. No packets or contents are collected.", "Permission and table-size failures leave coverage incomplete; absence is not inferred."])
    public init() {}
    public func collect() async -> CollectorSnapshot {
        let capacity = 16384; let rows = UnsafeMutablePointer<TWSocket>.allocate(capacity: capacity); defer { rows.deallocate() }
        var limited: Int32 = 0; let count = tw_sockets(rows, Int32(capacity), &limited)
        let observations = (0..<max(0, Int(count))).map { i -> Observation in
            let r = rows[i], tcp = r.tcp != 0, proto = r.tcp != 0 ? "TCP" : "UDP"
            let local = WindowsSources.string(r.local_address), remote = WindowsSources.string(r.remote_address)
            let listener = tcp && r.state == 2
            return Observation(key: "\(proto)|\(local)|\(r.local_port)|\(remote)|\(r.remote_port)|\(r.pid)", eventClass: listener ? .listener : .network,
                component: "\(proto) \(local):\(r.local_port)", attributes: ["protocol": proto, "localAddress": local, "localPort": String(r.local_port), "remoteAddress": remote.isEmpty ? "NOT APPLICABLE" : remote, "remotePort": tcp ? String(r.remote_port) : "NOT APPLICABLE", "ownerPID": String(r.pid), "state": listener ? "LISTENING" : tcp ? "TCP STATE \(r.state)" : "UDP BOUND", "executable": "UNKNOWN", "externalReachability": "UNKNOWN"], limitations: descriptor.limitations, confidence: .moderate)
        }
        return CollectorSnapshot(descriptor: descriptor, observations: observations, complete: limited == 0 && count >= 0, absenceReliable: false, state: limited == 0 && count >= 0 ? .degraded : .error, detail: "\(observations.count) socket records; owner PID only, AI attribution unknown; partial sources: \(limited != 0)")
    }
}
public struct AIFileAccessCollector: Collector {
    public static let id = "ai-open-files"
    public let descriptor = SensorDescriptor(id, "AI file access", source: "Windows file-event provider not implemented", monitors: "Future approved metadata-only file events", limitations: ["UNAVAILABLE. Resource usage and process names do not establish file access. No driver or privileged event session is installed."])
    public init() {}
    public func collect() async -> CollectorSnapshot { CollectorSnapshot(descriptor: descriptor, state: .unsupported, visibility: .unavailable, detail: "Windows file-access adapter not implemented") }
}
#endif
