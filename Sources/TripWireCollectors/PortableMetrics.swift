import Foundation
import TripWireCore
#if os(Windows)
import CTripWirePlatform
#else
import Glibc
#endif

public enum HostResourceSampler {
    public static func sample() -> HostResourceCounters {
        #if os(Windows)
        var value = TWHost(); _ = tw_host(&value)
        return HostResourceCounters(timestamp: Date(), uptime: ProcessInfo.processInfo.systemUptime,
            cpu: value.cpu_valid != 0 ? CPUTicks(user: value.user, system: value.system, idle: value.idle, nice: 0) : nil,
            ram: value.memory_valid != 0 ? RAMUsage(totalBytes: value.total_memory, availableBytes: value.available_memory, definition: "Windows physical total minus available; includes OS-managed reclaimability. Not macOS Memory Used.") : nil,
            pressure: MemoryPressureReading(state: .unknown, detail: "Windows memory-pressure grading is not implemented; RAM occupancy is not substituted for pressure."))
        #else
        let fields = LinuxProc.text("/proc/stat")?.split(separator: "\n").first(where: { $0.hasPrefix("cpu ") }).map { $0.split(whereSeparator: { $0.isWhitespace }).dropFirst().map(String.init) }
        let ticks = fields.flatMap { values -> [UInt64]? in
            let parsed = values.compactMap(UInt64.init)
            return parsed.count == values.count ? parsed : nil
        }
        var cpu: CPUTicks?
        if let t = ticks, t.count >= 8 {
            func sum(_ parts: [UInt64]) -> UInt64? {
                var result: UInt64 = 0
                for part in parts { let pair = result.addingReportingOverflow(part); guard !pair.overflow else { return nil }; result = pair.partialValue }
                return result
            }
            if let system = sum([t[2], t[5], t[6], t[7]]), let idle = sum([t[3], t[4]]) { cpu = CPUTicks(user: t[0], system: system, idle: idle, nice: t[1]) }
        }
        var memory: [String: UInt64] = [:]
        for line in LinuxProc.text("/proc/meminfo", limit: 65536)?.split(separator: "\n") ?? [] {
            let f = line.split(whereSeparator: { $0.isWhitespace })
            if f.count == 3, f[2] == "kB", let value = UInt64(f[1]), value <= UInt64.max / 1024 { memory[String(f[0].dropLast())] = value * 1024 }
        }
        let ram = memory["MemTotal"].flatMap { total in memory["MemAvailable"].flatMap { RAMUsage(totalBytes: total, availableBytes: $0, definition: "Linux MemTotal minus MemAvailable (kernel reclaimability estimate); scoped to /proc view, not a container memory limit.") } }
        return HostResourceCounters(timestamp: Date(), uptime: ProcessInfo.processInfo.systemUptime, cpu: cpu, ram: ram,
            pressure: MemoryPressureReading(state: .unknown, detail: "Linux PSI-to-pressure grading is not implemented; RAM occupancy is not substituted for pressure."))
        #endif
    }
}
