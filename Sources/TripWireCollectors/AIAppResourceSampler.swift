import AppKit
import Darwin
import TripWireCore

/// Read-only local app/process resource counters. No argv, environment, documents,
/// browser data, prompts, transcripts, payloads, screenshots or keystrokes.
public enum AIAppResourceSampler {
    @MainActor public static func applications() -> [AIApplication] {
        let names = Set(["Codex", "ChatGPT", "Claude", "Cursor", "Ollama", "LM Studio"])
        let ids = ["com.openai.codex": "Codex", "com.openai.chat": "ChatGPT"]
        var seen = Set<String>()
        return NSWorkspace.shared.runningApplications.compactMap { app in
            guard !app.isTerminated, let id = app.bundleIdentifier, let url = app.bundleURL,
                  let name = ids[id] ?? app.localizedName.flatMap({ names.contains($0) ? $0 : nil }),
                  seen.insert(id).inserted else { return nil }
            return AIApplication(id: id, name: name, bundlePath: url.path, pid: app.processIdentifier)
        }.prefix(32).sorted { $0.name < $1.name }
    }

    public struct ProcessMetadata: Sendable {
        public var pid: Int32, parent: Int32
        public var started: UInt64
        public var path: String
        public init(pid: Int32, parent: Int32, started: UInt64, path: String) {
            self.pid = pid; self.parent = parent; self.started = started; self.path = path
        }
    }
    /// Exact bundle-path boundaries seed attribution; parent links extend it only
    /// when the parent existed before the child. No name-only process matching.
    public static func owners(apps: [AIApplication], processes: [ProcessMetadata]) -> [Int32: String] {
        let byPID = Dictionary(processes.map { ($0.pid, $0) }, uniquingKeysWith: { first, _ in first })
        var result: [Int32: String] = [:]
        for process in processes {
            if let app = apps.first(where: { process.path.hasPrefix($0.bundlePath + "/") }) { result[process.pid] = app.id }
        }
        for _ in 0..<32 {
            var changed = false
            for process in processes where result[process.pid] == nil {
                if let parent = byPID[process.parent], parent.started <= process.started, let owner = result[parent.pid] {
                    result[process.pid] = owner; changed = true
                }
            }
            if !changed { break }
        }
        return result
    }
    static func metadata(_ pid: Int32) -> ProcessMetadata? {
        var info = proc_bsdinfo()
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size)) == MemoryLayout<proc_bsdinfo>.size,
              info.pbi_uid == getuid() else { return nil }
        // PROC_PIDPATHINFO_MAXSIZE is the C macro (4 * MAXPATHLEN), which
        // Swift cannot import as a constant expression on every SDK.
        var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        guard proc_pidpath(pid, &path, UInt32(path.count)) > 0 else { return nil }
        return ProcessMetadata(pid: pid, parent: Int32(info.pbi_ppid), started: info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec, path: String(cString: path))
    }
    public static func sample(apps: [AIApplication]) -> AppResourceSample {
        var timebase = mach_timebase_info_data_t()
        let validTimebase = mach_timebase_info(&timebase) == KERN_SUCCESS && timebase.denom > 0
        let factor = validTimebase ? Double(timebase.numer) / Double(timebase.denom) / 1_000_000_000 : 0
        var result = AppResourceSample(secondsPerTick: factor, coreCount: ProcessInfo.processInfo.activeProcessorCount, apps: apps, processes: [])
        guard validTimebase else { result.error = "Process clock unavailable"; return result }
        guard !apps.isEmpty else { return result }
        var pids = [Int32](repeating: 0, count: 4096)
        let capacity = pids.count * MemoryLayout<Int32>.stride
        let bytes = proc_listpids(UInt32(PROC_UID_ONLY), getuid(), &pids, Int32(capacity))
        guard bytes > 0 else { result.error = "Process inventory unavailable"; return result }
        result.limited = Int(bytes) >= capacity
        let processes = pids.prefix(min(pids.count, Int(bytes) / MemoryLayout<Int32>.stride)).filter { $0 > 0 }.compactMap { pid -> ProcessMetadata? in
            guard let value = metadata(pid) else { result.limited = true; return nil }
            return value
        }
        let owners = owners(apps: apps, processes: processes)
        for process in processes {
            guard let owner = owners[process.pid] else { continue }
            var usage = rusage_info_v2()
            let status = withUnsafeMutablePointer(to: &usage) { pointer in
                pointer.withMemoryRebound(to: rusage_info_t?.self, capacity: 1) {
                    proc_pid_rusage(process.pid, RUSAGE_INFO_V2, $0)
                }
            }
            // Recheck identity after sampling to avoid attributing a reused PID.
            guard status == 0, let after = metadata(process.pid), after.started == process.started, after.path == process.path else {
                result.limited = true; continue
            }
            let (ticks, overflow) = usage.ri_user_time.addingReportingOverflow(usage.ri_system_time)
            guard !overflow else { result.limited = true; continue }
            result.processes.append(AppProcessCounter(appID: owner, pid: process.pid, started: usage.ri_proc_start_abstime,
                                                     cpuTicks: ticks, footprint: usage.ri_phys_footprint))
        }
        result.timestamp = Date(); result.uptime = ProcessInfo.processInfo.systemUptime
        return result
    }
}
