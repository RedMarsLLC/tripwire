import Darwin
import Foundation
import TripWireCore

/// Bounded, aggregate, read-only Mach queries; no process arguments or payloads.
/// The caller schedules this only while the resource overlay is visible.
public enum HostResourceSampler {
    public static func sample() -> HostResourceCounters {
        let host = mach_host_self()
        defer { mach_port_deallocate(mach_task_self_, host) }
        var cpuInfo = host_cpu_load_info_data_t()
        var cpuCount = mach_msg_type_number_t(MemoryLayout<host_cpu_load_info_data_t>.stride / MemoryLayout<integer_t>.stride)
        let cpuResult = withUnsafeMutablePointer(to: &cpuInfo) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(cpuCount)) {
                host_statistics(host, HOST_CPU_LOAD_INFO, $0, &cpuCount)
            }
        }
        let ticks: CPUTicks? = cpuResult == KERN_SUCCESS ? CPUTicks(
            user: UInt64(cpuInfo.cpu_ticks.0), system: UInt64(cpuInfo.cpu_ticks.1),
            idle: UInt64(cpuInfo.cpu_ticks.2), nice: UInt64(cpuInfo.cpu_ticks.3)
        ) : nil
        var vmInfo = vm_statistics64_data_t()
        var vmCount = mach_msg_type_number_t(MemoryLayout<vm_statistics64_data_t>.stride / MemoryLayout<integer_t>.stride)
        let vmResult = withUnsafeMutablePointer(to: &vmInfo) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(vmCount)) {
                host_statistics64(host, HOST_VM_INFO64, $0, &vmCount)
            }
        }
        var pageSize: vm_size_t = 0
        let pageResult = host_page_size(host, &pageSize)
        let ram = vmResult == KERN_SUCCESS && pageResult == KERN_SUCCESS ? RAMUsage(
            totalBytes: ProcessInfo.processInfo.physicalMemory, freePages: UInt64(vmInfo.free_count), pageSize: UInt64(pageSize), fileBackedPages: UInt64(vmInfo.external_page_count),
            compressedPages: UInt64(vmInfo.compressor_page_count), wiredPages: UInt64(vmInfo.wire_count), anonymousPages: UInt64(vmInfo.internal_page_count), purgeablePages: UInt64(vmInfo.purgeable_count)
        ) : nil
        return HostResourceCounters(timestamp: Date(), uptime: ProcessInfo.processInfo.systemUptime, cpu: ticks, ram: ram, swap: vmResult == KERN_SUCCESS && pageResult == KERN_SUCCESS ? SwapCounters(pageIns: vmInfo.swapins, pageOuts: vmInfo.swapouts, pageSize: UInt64(pageSize)) : nil, pressure: memoryPressure())
    }

    /// XNU's read-only diagnostic exposes Dispatch pressure levels (1/2/4).
    /// This is version-dependent, not a stable documented application API. Do not
    /// substitute a RAM occupancy estimate or a missing notification for a grade.
    public static func memoryPressure() -> MemoryPressureReading {
        var value: UInt32 = 0
        var size = MemoryLayout<UInt32>.size
        let result = sysctlbyname("kern.memorystatus_vm_pressure_level", &value, &size, nil, 0)
        let error = result == 0 ? 0 : errno
        return decodePressure(value: value, size: size, error: error)
    }

    static func decodePressure(value: UInt32, size: Int, error: Int32) -> MemoryPressureReading {
        if error != 0 {
            let reason: String
            switch error {
            case EPERM, EACCES: reason = "macOS denied the current-pressure read in this process."
            case ENOENT, ENOTSUP: reason = "This macOS environment does not expose the current-pressure diagnostic."
            default: reason = "The macOS current-pressure read failed (error \(error))."
            }
            return MemoryPressureReading(state: .unknown, detail: reason + " TripWire retries while the overlay is visible. Check Activity Monitor → Memory for the system view.")
        }
        let state: MemoryPressure
        switch (size, value) {
        case (MemoryLayout<UInt32>.size, 1): state = .normal
        case (MemoryLayout<UInt32>.size, 2): state = .warning
        case (MemoryLayout<UInt32>.size, 4): state = .critical
        default: return MemoryPressureReading(state: .unknown, detail: "macOS returned an unrecognized pressure result (value \(value), size \(size)). TripWire needs support for this format; check Activity Monitor → Memory.")
        }
        return MemoryPressureReading(state: state, detail: "Current macOS memory-pressure level, read from kern.memorystatus_vm_pressure_level. This OS diagnostic can change between macOS releases. It is independent of RAM occupancy and does not identify which app caused pressure.")
    }
}
