import Foundation
import TripWireCore

public struct SocketRow: Equatable {
    public var pid: Int32
    public var uid: UInt32?
    public var name: String
    public var proto: String
    public var endpoint: String
    public var state: String
}
public enum LsofParser {
    public static func parse(_ data: Data) -> (rows: [SocketRow], invalid: Bool) {
        var pid: Int32?, uid: UInt32?, name = "UNKNOWN", proto = "", endpoint = "", state = "", hasFD = false
        var rows: [SocketRow] = [], invalid = false
        func flush() {
            guard hasFD else { return }
            if let pid, ["TCP", "UDP"].contains(proto), !endpoint.isEmpty { rows.append(SocketRow(pid: pid, uid: uid, name: name, proto: proto, endpoint: endpoint, state: state.isEmpty ? "UNKNOWN" : state)) }
            else { invalid = true }
            hasFD = false; proto = ""; endpoint = ""; state = ""
        }
        for token in String(decoding: data, as: UTF8.self).split(separator: "\0", omittingEmptySubsequences: true) {
            let field = token.drop(while: { $0 == "\n" })
            guard let tag = field.first else { continue }; let value = String(field.dropFirst())
            switch tag {
            case "p": flush(); pid = Int32(value); uid = nil; name = "UNKNOWN"
            case "u": uid = UInt32(value)
            case "c": name = value
            case "f": flush(); hasFD = true
            case "P": proto = value
            case "n": endpoint = value
            case "T": if value.hasPrefix("ST=") { state = String(value.dropFirst(3)) }
            default: break
            }
        }
        flush(); return (rows, invalid)
    }
    public static func address(_ endpoint: String) -> (address: String, port: String) {
        guard let colon = endpoint.lastIndex(of: ":") else { return (endpoint, "UNKNOWN") }
        return (String(endpoint[..<colon]).trimmingCharacters(in: CharacterSet(charactersIn: "[]")), String(endpoint[endpoint.index(after: colon)...]))
    }
}
public struct NetworkCollector: Collector {
    public let descriptor = SensorDescriptor("network", "Connections and listeners", source: "lsof(8) NUL-delimited fields, ps(1), Security signing metadata", monitors: "Visible TCP sockets and UDP bindings at sample time", limitations: ["Polling misses short-lived sockets; counts are observations, not connection frequency.", "UDP binding is not TCP LISTEN and does not prove transmitted or received traffic.", "LISTENING does not establish external reachability. No network scans are performed.", "Interface, packet headers, bytes, payloads, and remote reachability are NOT OBSERVABLE here.", "PID attribution is best-effort and races process exit/reuse; responsible application may differ from socket owner.", "Non-root visibility is incomplete; no removals are inferred from this source."])
    public init() {}
    public func collect() async -> CollectorSnapshot {
        let command = ReadCommand.run("/usr/sbin/lsof", ["-nP", "-iTCP", "-iUDP", "-F0pcufPnT"])
        let parsed = LsofParser.parse(command.output)
        let processes = ProcessParser.snapshot().processes
        let byPID = Dictionary(processes.compactMap { p in p.pid.map { ($0, p) } }, uniquingKeysWith: { a, _ in a })
        var signatures: [String: ProcessIdentity] = [:]
        let observations = parsed.rows.map { row -> Observation in
            let pair = row.endpoint.components(separatedBy: "->")
            let local = LsofParser.address(pair[0]), remote = pair.count == 2 ? LsofParser.address(pair[1]) : (address: "UNKNOWN", port: "UNKNOWN")
            let listener = row.proto == "TCP" && row.state == "LISTEN"
            var process = byPID[row.pid] ?? ProcessIdentity(pid: row.pid, uid: row.uid)
            if let path = process.executablePath {
                if signatures[path] == nil { signatures[path] = Signature.identity(path) }
                process.teamID = signatures[path]?.teamID; process.signingIdentity = signatures[path]?.signingIdentity; process.signatureStatus = signatures[path]?.signatureStatus
            }
            let owner = process.executablePath ?? "UNKNOWN:\(row.pid)"
            let key = [row.proto, owner, local.address, local.port, remote.address, remote.port].joined(separator: "|")
            return Observation(key: key, eventClass: listener ? .listener : .network, component: "\(row.name) \(row.proto) \(row.endpoint)", attributes: ["protocol": row.proto, "localAddress": local.address, "localPort": local.port, "remoteAddress": remote.address, "remotePort": remote.port, "state": listener ? "LISTENING" : row.proto == "UDP" && pair.count == 1 ? "UDP BOUND" : row.state, "externalReachability": "UNKNOWN", "interface": "UNKNOWN", "executable": owner, "teamID": process.teamID ?? "UNKNOWN", "signingIdentity": process.signingIdentity ?? "UNKNOWN", "user": row.uid.map(String.init) ?? "UNKNOWN"], process: process, limitations: descriptor.limitations, confidence: .moderate)
        }
        let valid = command.successful && command.error.isEmpty && !parsed.invalid
        // lsof exit 1 and empty output are ambiguous, not a reassuring empty inventory.
        return CollectorSnapshot(descriptor: descriptor, observations: observations, complete: valid, absenceReliable: false, state: valid ? .degraded : .error, detail: valid ? "Visible socket snapshot; baseline covers observations only, absence remains UNKNOWN" : "lsof failed, warned, timed out or format unrecognized; absence is UNKNOWN")
    }
}
