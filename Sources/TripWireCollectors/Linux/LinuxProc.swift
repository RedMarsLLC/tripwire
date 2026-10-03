#if os(Linux)
import Foundation
import Glibc
import TripWireCore

/// Only fixed kernel metadata files; never cmdline, environ, maps or target file contents.
enum LinuxProc {
    static let root = URL(fileURLWithPath: "/proc")
    static func text(_ path: String, limit: Int = 1_048_576) -> String? {
        guard let file = try? FileHandle(forReadingFrom: URL(fileURLWithPath: path)) else { return nil }
        defer { try? file.close() }
        guard let data = try? file.read(upToCount: limit + 1), data.count <= limit else { return nil }
        return String(data: data, encoding: .utf8)
    }
    static func bootTime() -> Double? {
        text("/proc/stat")?.split(separator: "\n").first(where: { $0.hasPrefix("btime ") }).flatMap { Double($0.split(separator: " ").last ?? "") }
    }
    static func statFields(_ text: String) -> (pid: Int32, parent: Int32, started: UInt64, cpu: UInt64)? {
        guard let left = text.firstIndex(of: "("), let right = text.lastIndex(of: ")"), left < right,
              let pid = Int32(text[..<left].trimmingCharacters(in: .whitespaces)) else { return nil }
        let fields = text[text.index(after: right)...].split(whereSeparator: { $0.isWhitespace })
        guard fields.count > 21, let parent = Int32(fields[1]), let user = UInt64(fields[11]),
              let system = UInt64(fields[12]), let started = UInt64(fields[19]) else { return nil }
        let sum = user.addingReportingOverflow(system); guard !sum.overflow else { return nil }
        return (pid, parent, started, sum.partialValue)
    }
    static func hasSameUID(_ pid: Int32, uid: UInt32) -> Bool {
        guard let line = text("/proc/\(pid)/status", limit: 16384)?.split(separator: "\n").first(where: { $0.hasPrefix("Uid:") }) else { return false }
        let values = line.split(whereSeparator: { $0.isWhitespace }).dropFirst()
        return values.count == 4 && values.allSatisfy { UInt32($0) == uid }
    }
    struct Entry { var identity: ProcessIdentity; var ticks: UInt64; var started: UInt64 }
    static func entry(_ pid: Int32, boot: Double, hz: Double) -> Entry? {
        let base = "/proc/\(pid)"
        guard let before = text(base + "/stat", limit: 8192).flatMap(statFields), before.pid == pid else { return nil }
        let uid = text(base + "/status", limit: 16384)?.split(separator: "\n").first(where: { $0.hasPrefix("Uid:") }).flatMap { UInt32($0.split(whereSeparator: { $0.isWhitespace }).dropFirst().first ?? "") }
        let path = try? FileManager.default.destinationOfSymbolicLink(atPath: base + "/exe")
        guard let after = text(base + "/stat", limit: 8192).flatMap(statFields), after.pid == pid, before.started == after.started, before.parent == after.parent else { return nil }
        return Entry(identity: ProcessIdentity(pid: pid, parentPID: before.parent, uid: uid,
            executablePath: path, launchTime: Date(timeIntervalSince1970: boot + Double(before.started) / hz)), ticks: after.cpu, started: before.started)
    }
    static func snapshot() -> (entries: [Entry], limited: Bool) {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: "/proc"), let boot = bootTime(), boot > 0 else { return ([], true) }
        let hz = Double(sysconf(Int32(_SC_CLK_TCK))); guard hz > 0 else { return ([], true) }
        let ids = names.compactMap(Int32.init).sorted(); var limited = ids.count > 8192
        let entries = ids.prefix(8192).compactMap { pid -> Entry? in
            guard let entry = entry(pid, boot: boot, hz: hz) else { limited = true; return nil }; return entry
        }
        return (entries, limited)
    }
}
public struct ProcessCollector: Collector {
    public let descriptor = SensorDescriptor("processes", "Process snapshots", source: "Linux /proc PID/stat, status and exe metadata",
        monitors: "Visible PIDs, parent PIDs, UID, boot-relative start time and executable link",
        limitations: ["Polling misses brief processes; visibility is limited by permissions and PID namespaces.", "Executable links may be unreadable. Arguments, environment and process memory are not collected.", "Process names and executable paths are not attestation or proof of AI intent."])
    public init() {}
    public func collect() async -> CollectorSnapshot {
        let snapshot = LinuxProc.snapshot()
        let rows = snapshot.entries.map { entry in
            let p = entry.identity
            return Observation(key: p.instanceKey ?? "unknown:\(p.pid ?? -1):\(entry.started)", eventClass: .process, component: p.executablePath ?? "PID \(p.pid ?? -1) · executable unknown",
                attributes: ["executable": p.executablePath ?? "UNKNOWN", "uid": p.uid.map(String.init) ?? "UNKNOWN", "signature": "NOT OBSERVABLE"], process: p, limitations: descriptor.limitations, confidence: .moderate)
        }
        return CollectorSnapshot(descriptor: descriptor, observations: rows, complete: !snapshot.limited, absenceReliable: false,
            state: snapshot.limited ? .error : .degraded, detail: "\(rows.count) process snapshots; \(snapshot.limited ? "partial/failed inventory" : "visible PID namespace only"). No process-exit inference.")
    }
}
public struct LinuxKernelCollector: Collector {
    public let descriptor = SensorDescriptor("kernel-modules", "Loaded kernel modules", source: "Linux /proc/modules",
        monitors: "Names of dynamically loaded kernel modules visible in this environment",
        limitations: ["Built-in drivers, installed-but-unloaded modules and load events between polls are outside scope.", "A module's presence does not identify its installer or responsible AI agent. Containers may share the host kernel."])
    public init() {}
    public func collect() async -> CollectorSnapshot {
        guard let text = LinuxProc.text("/proc/modules") else { return CollectorSnapshot(descriptor: descriptor, state: .error, detail: "Module inventory unreadable; absence unknown") }
        var failed = false
        let rows = text.split(separator: "\n").compactMap { line -> Observation? in
            let f = line.split(whereSeparator: { $0.isWhitespace }); guard f.count >= 6, UInt64(f[1]) != nil else { failed = true; return nil }
            let name = String(f[0])
            return Observation(key: name, eventClass: .extensions, component: name, attributes: ["name": name, "loadedState": String(f[4]), "sizeBytes": String(f[1])], limitations: descriptor.limitations, confidence: .moderate)
        }
        return CollectorSnapshot(descriptor: descriptor, observations: rows, complete: !failed, absenceReliable: false, state: failed ? .error : .degraded, detail: "Loaded module snapshot only; installation and AI attribution unknown")
    }
}
#endif
