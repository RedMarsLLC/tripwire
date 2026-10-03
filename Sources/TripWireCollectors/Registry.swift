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

public final class Monitor {
    public let store: EventStore
    public let collectors: [any Collector]
    private var lockFD: Int32 = -1
    private var sessionStarted = false
    private var fileWatch: FileWatchSession?
    public init(store: EventStore, collectors: [any Collector]? = nil) { self.store = store; self.collectors = collectors ?? CollectorRegistry.make(storeURL: store.url) }
    deinit { release() }
    public func acquire() throws {
        guard !store.isReadOnly else { throw TripWireError.message("Collectors require an explicit writable store connection") }
        guard lockFD < 0 else { return }
        let fd = open(store.url.path + ".collector-lock", O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw TripWireError.message("Cannot open collector lock") }
        var attributes = stat()
        guard fstat(fd, &attributes) == 0, attributes.st_mode & S_IFMT == S_IFREG, attributes.st_uid == geteuid(), attributes.st_nlink == 1, attributes.st_mode & 0o077 == 0 else {
            close(fd); throw TripWireError.message("Collector lock must be a private regular file owned by this user")
        }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { close(fd); throw TripWireError.message("Another collector owner is running. This interface can read the shared store.") }
        lockFD = fd
    }
    public func release() { fileWatch?.stop(); fileWatch = nil; if lockFD >= 0 { flock(lockFD, LOCK_UN); close(lockFD); lockFD = -1 } }
    public func sample(continuousFiles: Bool = false) async throws {
        try acquire()
        let now = Date()
        if !sessionStarted {
            if let session = try store.metadata("openCollectorSession"), !session.isEmpty {
                let prior = Double(try store.metadata("lastSample") ?? "") ?? now.timeIntervalSince1970
                try store.recordGap(CoverageGap(collector: "watchdog", start: Date(timeIntervalSince1970: prior), end: now, reason: "Previous collector session ended without a recorded stop; coverage cannot be guaranteed"))
            }
            try store.setMetadata("openCollectorSession", UUID().uuidString)
            sessionStarted = true
        }
        try store.closeGaps(collector: "watchdog", at: now)
        if let prior = try store.metadata("lastSample"), let seconds = Double(prior), now.timeIntervalSince1970 - seconds > 90 {
            let oldUptime = Double(try store.metadata("lastUptime") ?? "") ?? 0
            let reboot = ProcessInfo.processInfo.systemUptime < oldUptime
            try store.recordGap(CoverageGap(collector: "watchdog", start: Date(timeIntervalSince1970: seconds), end: now, reason: reboot ? "Uptime decreased: reboot or clock/uptime discontinuity; coverage cannot be guaranteed" : "Monitoring interval exceeded 90 seconds: stopped process, sleep or scheduling delay; cause UNKNOWN"))
        }
        try store.setMetadata("lastSample", String(now.timeIntervalSince1970))
        try store.setMetadata("lastUptime", String(ProcessInfo.processInfo.systemUptime))
        if continuousFiles && fileWatch == nil, let collector = collectors.first(where: { $0.descriptor.id == AIFileAccessCollector.id }) {
            fileWatch = FileWatchSession(store: store, collector: collector)
        }
        try fileWatch?.check()
        // Each source runs independently. A failed source returns its own health and does not cancel siblings.
        let currentFileWatch = fileWatch
        await withTaskCancellationHandler {
            await withTaskGroup(of: CollectorSnapshot.self) { group in
                for collector in collectors where currentFileWatch == nil || collector.descriptor.id != AIFileAccessCollector.id { group.addTask { await collector.collect() } }
                for await snapshot in group {
                    do { try store.ingest(snapshot) }
                    catch { collectionErrors.append("\(snapshot.descriptor.id): \(error)") }
                }
            }
        } onCancel: {
            // Stop the independent file loop promptly even if a synchronous
            // general inventory is still finishing its current OS call.
            currentFileWatch?.stop()
        }
        guard collectionErrors.isEmpty else { let failures = collectionErrors; collectionErrors = []; throw TripWireError.message("Event-store write failures: " + failures.joined(separator: "; ")) }
        try fileWatch?.check()
        try store.correlateRecent()
        try store.setMetadata("lastCompletedSample", String(Date().timeIntervalSince1970))
    }
    private var collectionErrors: [String] = []
    public func stop() throws {
        guard lockFD >= 0 else { return }
        defer { release() }
        fileWatch?.stop()
        for var health in try store.sensors() where [.active, .degraded].contains(health.state) {
            health.state = .stopped; health.detail = "Collector owner stopped; last result: " + health.detail; try store.saveHealth(health)
        }
        try store.recordGap(CoverageGap(collector: "watchdog", start: Date(), reason: "Collector owner stopped; no continuous monitoring"))
        try store.setMetadata("openCollectorSession", "")
        sessionStarted = false
    }
}
