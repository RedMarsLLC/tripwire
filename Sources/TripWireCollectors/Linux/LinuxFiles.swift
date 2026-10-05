#if os(Linux)
import Foundation
import Glibc
import TripWireCore

public struct AIFileAccessCollector: Collector {
    public static let id = "ai-open-files"
    public let descriptor = SensorDescriptor(id, "File-handle snapshots", source: "Linux same-UID /proc process and descriptor metadata",
        monitors: "Regular-file and directory descriptors held by recognized AI executable names and observed descendants, plus configured current-account boundaries",
        limitations: ["Executable-name recognition can be spoofed and is not signing or AI-prompt attestation.", "Snapshots miss brief opens, detached descendants, unrecognized agents, other users and inaccessible processes.", "Descriptor metadata can race closes/reuse. Open mode is capability, not evidence of a read/write; inherited descriptors are possible. No target contents are read."])
    private let storeURL: URL?
    public init(storeURL: URL? = nil) { self.storeURL = storeURL }
    public func collect() async -> CollectorSnapshot {
        let rules: [TripwireRule]
        do { rules = try storeURL.map { try EventStore(url: $0, access: .readOnly).tripwireRules() } ?? [] }
        catch { return CollectorSnapshot(descriptor: descriptor, state: .error, visibility: .unknown, detail: "Tripwire configuration could not be read; file scope is unknown.") }
        let accountRules = rules.filter { $0.enabled && $0.platform == .linux && $0.effectiveScope == .currentUser }
        let snapshot = LinuxProc.snapshot(), uid = geteuid()
        let entries = snapshot.entries.filter { $0.identity.uid == uid && $0.identity.pid.map { LinuxProc.hasSameUID($0, uid: uid) } == true }
        let byPID = Dictionary(entries.compactMap { e in e.identity.pid.map { ($0, e) } }, uniquingKeysWith: { a, _ in a })
        let names: Set<String> = ["codex", "claude", "cursor", "ollama", "lm-studio", "chatgpt"]
        func owner(_ entry: LinuxProc.Entry) -> (LinuxProc.Entry, [LinuxProc.Entry])? {
            var next = entry, visited: Set<Int32> = [], chain: [LinuxProc.Entry] = []
            while let pid = next.identity.pid, visited.insert(pid).inserted, visited.count <= 32 {
                chain.append(next)
                if let path = next.identity.executablePath, names.contains(URL(fileURLWithPath: path).lastPathComponent.lowercased()) { return (next, chain) }
                guard let parent = next.identity.parentPID.flatMap({ byPID[$0] }), parent.started <= next.started else { return nil }
                next = parent
            }
            return nil
        }
        var targets = entries.compactMap { entry -> (LinuxProc.Entry, LinuxProc.Entry?, [LinuxProc.Entry])? in
            if let ai = owner(entry) { return (entry, ai.0, ai.1) }
            return accountRules.isEmpty ? nil : (entry, nil, [entry])
        }
        if !accountRules.isEmpty && targets.count > 128 {
            targets.sort { ($0.0.identity.pid ?? 0) < ($1.0.identity.pid ?? 0) }
            let offset = (Int(ProcessInfo.processInfo.systemUptime / 2) * 128) % targets.count
            targets = Array(targets[offset...] + targets[..<offset])
        }
        var limited = snapshot.limited || targets.count > 128, observations: [Observation] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        for (entry, agent, chain) in targets.prefix(128) {
            guard let pid = entry.identity.pid,
                  let fds = try? FileManager.default.contentsOfDirectory(atPath: "/proc/\(pid)/fd") else { limited = true; continue }
            if fds.count > 4096 { limited = true }
            var pending: [Observation] = []
            for fd in fds.prefix(4096) where Int(fd) != nil {
                let source = "/proc/\(pid)/fd/\(fd)"
                var metadata = stat()
                guard stat(source, &metadata) == 0 else { limited = true; continue }
                let objectType = metadata.st_mode & S_IFMT
                guard objectType == S_IFREG || objectType == S_IFDIR else { continue }
                guard let path = try? FileManager.default.destinationOfSymbolicLink(atPath: source), path.hasPrefix("/") else { limited = true; continue }
                guard agent != nil || accountRules.contains(where: { TripwirePath.matches(path, rule: $0) }) else { continue }
                let flags = LinuxProc.text("/proc/\(pid)/fdinfo/\(fd)", limit: 8192)?.split(separator: "\n").first(where: { $0.hasPrefix("flags:") }).flatMap { UInt32($0.split(whereSeparator: { $0.isWhitespace }).last ?? "", radix: 8) }
                let mode: String
                if let flags { mode = flags & UInt32(0o10000000) /* Linux O_PATH; Glibc Swift module omits this GNU macro */ != 0 ? "PATH ONLY (not read/write)" : flags & 3 == 0 ? "READ CAPABLE" : flags & 3 == 1 ? "WRITE CAPABLE" : flags & 3 == 2 ? "READ/WRITE CAPABLE" : "UNKNOWN" } else { mode = "UNKNOWN"; limited = true }
                var after = stat()
                guard stat(source, &after) == 0, after.st_dev == metadata.st_dev, after.st_ino == metadata.st_ino,
                      (try? FileManager.default.destinationOfSymbolicLink(atPath: source)) == path else { limited = true; continue }
                var attrs = ["path": path, "pid": String(pid), "executable": entry.identity.executablePath ?? "UNKNOWN", "collectorUID": String(uid), "operation": "Open descriptor sampled; actual read/write unknown", "openMode": mode]
                if let agentPath = agent?.identity.executablePath {
                    attrs["associatedApp"] = URL(fileURLWithPath: agentPath).lastPathComponent
                    attrs["associationBasis"] = "Executable-name recognition plus observed same-UID ancestry; not attestation"
                }
                if let parent = chain.dropFirst().first { attrs["parentExecutable"] = parent.identity.executablePath }
                if let reason = FileAccessReview.reason(path: path, home: home, platform: .linux) { attrs["reviewReason"] = reason }
                attrs["objectType"] = objectType == S_IFDIR ? "Directory" : "Regular file"
                pending.append(Observation(key: "\(entry.identity.instanceKey ?? String(pid))|\(path)|\(mode)", eventClass: .file, component: path, attributes: attrs, process: entry.identity, limitations: descriptor.limitations, confidence: .moderate))
                if pending.count + observations.count >= 2048 { limited = true; break }
            }
            let stable = chain.allSatisfy { old in
                guard let oldPID = old.identity.pid, let current = LinuxProc.text("/proc/\(oldPID)/stat", limit: 8192).flatMap(LinuxProc.statFields),
                      current.started == old.started, current.parent == old.identity.parentPID, LinuxProc.hasSameUID(oldPID, uid: uid),
                      let path = try? FileManager.default.destinationOfSymbolicLink(atPath: "/proc/\(oldPID)/exe") else { return false }
                return path == old.identity.executablePath
            }
            if stable { observations += pending } else { limited = true }
            if observations.count >= 2048 { break }
        }
        // Multiple descriptors can hold the same file with the same capability.
        observations = Array(Dictionary(observations.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a }).values)
        return CollectorSnapshot(descriptor: descriptor, observations: observations, complete: !limited, absenceReliable: false, state: limited ? .error : .degraded,
            detail: "\(observations.count) observed file handles; \(limited ? "partial/racing inventory" : "scoped snapshots only"). Zero records does not establish no file access.")
    }
}
#endif
