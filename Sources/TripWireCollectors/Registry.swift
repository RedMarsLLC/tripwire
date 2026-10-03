import Foundation
import TripWireCore

public enum CollectorRegistry {
    public static func make(storeURL: URL) -> [any Collector] {
        [SelfIntegrityCollector(storeURL: storeURL), ProcessCollector(), AIFileAccessCollector(), NetworkCollector(), ApplicationCollector(), PersistenceCollector(), ExtensionCollector(), KernelBundleCollector(), HardwareCollector(), ConfigurationCollector(), CanaryCollector(directory: storeURL.deletingLastPathComponent().appendingPathComponent("Canaries"))
        ] + unavailable.map { $0 as any Collector }
    }
    /// Declared implementation gaps, distinct from a temporarily unreadable source.
    public static let unavailable: [UnavailableCollector] = [
        UnavailableCollector(SensorDescriptor("endpoint-security", "OS file/process event audit / Endpoint Security", source: "Endpoint Security (adapter not installed)", monitors: "Future NOTIFY-only file-open/write/rename/delete and process events", permissions: ["Apple-granted com.apple.developer.endpoint-security.client", "Appropriate signing/provisioning", "Full Disk Access and ES client privilege requirements"], limitations: ["No ES client is created by this build. Sequence loss is UNKNOWN; a tested tracker is provided for future integration."]), reason: "UNAVAILABLE — ENTITLEMENT REQUIRED; live adapter not implemented", state: .permissionMissing),
         UnavailableCollector(SensorDescriptor("network-extension", "Network Extension / packet metadata", source: "NetworkExtension (provider not installed)", monitors: "Future permitted flow/header metadata", permissions: ["Network Extension entitlement", "Signed provider deployment", "Explicit system extension/filter approval"], limitations: ["No packet capture or header analysis. No filter is installed. No payload collection."]), reason: "UNAVAILABLE — ENTITLEMENT REQUIRED; provider not implemented", state: .permissionMissing),
         UnavailableCollector(SensorDescriptor("camera", "Camera activity", source: "No global activity adapter in Phase 1", monitors: "Future version-gated device activity indications", limitations: ["Current use and responsible process UNKNOWN. Capture permission is not resource use."]), reason: "NOT OBSERVABLE — camera activity adapter deferred"),
         UnavailableCollector(SensorDescriptor("microphone", "Microphone activity", source: "No global input activity adapter in Phase 1", monitors: "Future version-gated Core Audio process/input metadata", limitations: ["Device-running state is not proof of physical microphone capture. Attribution UNKNOWN."]), reason: "NOT OBSERVABLE — input activity adapter deferred"),
         UnavailableCollector(SensorDescriptor("privacy", "TCC / screen capture", source: "No supported global TCC query in this build", monitors: "Future entitled privacy events where supported", limitations: ["No TCC database reads. No screen capture. Other apps' permissions/activity UNKNOWN."]), reason: "NOT OBSERVABLE — global privacy state and screen capture attribution"),
         UnavailableCollector(SensorDescriptor("background-items", "Login / background items and profiles", source: "Registered inventory adapter deferred", monitors: "Future supported diagnostics with minimized metadata", limitations: ["SMAppService describes the calling app's services, not a global login item inventory.", "Configuration profile contents, cron registrations and browser persistence not collected."]), reason: "UNAVAILABLE — registered background/login items and profile inventory deferred")
    ]
}
