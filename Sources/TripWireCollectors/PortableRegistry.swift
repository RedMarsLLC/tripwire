import Foundation
import TripWireCore

public enum CollectorRegistry {
    public static func make(storeURL: URL) -> [any Collector] {
        var sources: [any Collector] = [ProcessCollector(), NetworkCollector()]
        #if os(Linux)
        sources += [AIFileAccessCollector(storeURL: storeURL), LinuxKernelCollector()]
        #endif
        return sources + unavailable.map { $0 as any Collector }
    }
    public static var unavailable: [UnavailableCollector] {
        var entries = [
            ("applications", "Installed applications", "Package/application inventory"),
            ("persistence", "Startup mechanisms", "Registered services, scheduled jobs and startup entries"),
            ("hardware", "Hardware changes", "Device inventory"),
            ("configuration", "Security configuration", "OS-specific posture and network configuration"),
            ("watchdog-integrity", "Watchdog integrity", "Own executable and evidence-store integrity inventory"),
            ("file-event-audit", "File/process event audit", "Exact file events and process ancestry"),
            ("canaries", "Canary markers", "Explicitly enrolled local markers")
        ]
        #if os(Windows)
        entries += [(AIFileAccessCollector.id, "AI file access", "Open-file snapshots or an approved event provider"), ("kernel-drivers", "Kernel drivers", "Installed/loaded driver inventory")]
        #endif
        return entries.map { id, name, scope in
            UnavailableCollector(SensorDescriptor(id, name, source: "\(HostPlatform.current.displayName) adapter not implemented", monitors: scope,
                limitations: ["UNAVAILABLE in this port. Starting monitoring or running as administrator/root does not implement this source.", "No privileged provider, service, driver or permission grant is installed."]), reason: "UNAVAILABLE — platform adapter not implemented")
        }
    }
}
