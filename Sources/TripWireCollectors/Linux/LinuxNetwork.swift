#if os(Linux)
import Foundation
import TripWireCore

struct LinuxSocket: Equatable {
    var tcp: Bool; var localAddress: String; var localPort: UInt16
    var remoteAddress: String; var remotePort: UInt16; var state: String; var inode: String
    static func endpoint(_ value: Substring) -> (String, UInt16)? {
        let pair = value.split(separator: ":"); guard pair.count == 2, let port = UInt16(pair[1], radix: 16) else { return nil }
        let hex = String(pair[0]); guard hex.count == 8 || hex.count == 32 else { return nil }
        var bytes: [UInt8] = []
        for offset in stride(from: 0, to: hex.count, by: 8) {
            guard let word = UInt32(hex.dropFirst(offset).prefix(8), radix: 16) else { return nil }
            // /proc renders each address word in host byte order (supported Linux targets are LE).
            bytes += [UInt8(truncatingIfNeeded: word), UInt8(truncatingIfNeeded: word >> 8), UInt8(truncatingIfNeeded: word >> 16), UInt8(truncatingIfNeeded: word >> 24)]
        }
        if bytes.count == 4 { return (bytes.map(String.init).joined(separator: "."), port) }
        return (stride(from: 0, to: 16, by: 2).map { String(format: "%x", UInt16(bytes[$0]) << 8 | UInt16(bytes[$0 + 1])) }.joined(separator: ":"), port)
    }
    static func parse(_ text: String, tcp: Bool) -> ([Self], Bool) {
        let lines = text.split(separator: "\n"); guard lines.first?.contains("local_address") == true else { return ([], false) }
        var valid = true
        let rows = lines.dropFirst().compactMap { line -> Self? in
            let f = line.split(whereSeparator: { $0.isWhitespace })
            guard f.count >= 10, let local = endpoint(f[1]), let remote = endpoint(f[2]), UInt8(f[3], radix: 16) != nil, UInt64(f[9]) != nil else { valid = false; return nil }
            return Self(tcp: tcp, localAddress: local.0, localPort: local.1, remoteAddress: remote.0, remotePort: remote.1, state: String(f[3]), inode: String(f[9]))
        }
        return (rows, valid)
    }
}
public struct NetworkCollector: Collector {
    public let descriptor = SensorDescriptor("network", "Connections and listeners", source: "Linux /proc/net/{tcp,tcp6,udp,udp6}",
        monitors: "TCP socket states and UDP bindings in the current network namespace",
        limitations: ["Snapshot only; brief sockets and other network namespaces may be missed.", "Socket-to-process and AI attribution are UNKNOWN in this adapter. No contents or packets are collected.", "Listening/bound ports do not establish external reachability. Absence is never inferred."])
    public init() {}
    public func collect() async -> CollectorSnapshot {
        var rows: [LinuxSocket] = [], valid = true
        for file in ["tcp", "tcp6", "udp", "udp6"] {
            guard let text = LinuxProc.text("/proc/net/" + file, limit: 4_194_304) else { valid = false; continue }
            let parsed = LinuxSocket.parse(text, tcp: file.hasPrefix("tcp")); rows += parsed.0; valid = valid && parsed.1
        }
        if rows.count > 16384 { rows = Array(rows.prefix(16384)); valid = false }
        let observations = rows.map { row in
            let listener = row.tcp && row.state == "0A", proto = row.tcp ? "TCP" : "UDP"
            let key = "\(row.inode)|\(proto)|\(row.localAddress)|\(row.localPort)|\(row.remoteAddress)|\(row.remotePort)"
            return Observation(key: key, eventClass: listener ? .listener : .network, component: "\(proto) \(row.localAddress):\(row.localPort)",
                attributes: ["protocol": proto, "localAddress": row.localAddress, "localPort": String(row.localPort), "remoteAddress": row.remoteAddress, "remotePort": String(row.remotePort), "state": listener ? "LISTENING" : row.tcp ? "TCP STATE 0x" + row.state : "UDP BOUND", "executable": "UNKNOWN", "externalReachability": "UNKNOWN"], limitations: descriptor.limitations, confidence: .moderate)
        }
        return CollectorSnapshot(descriptor: descriptor, observations: observations, complete: valid, absenceReliable: false, state: valid ? .degraded : .error, detail: "\(rows.count) socket records; \(valid ? "current network namespace" : "partial/malformed/oversized sources"); process attribution unknown")
    }
}
#endif
