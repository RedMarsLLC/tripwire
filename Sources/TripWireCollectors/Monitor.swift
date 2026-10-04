import Foundation
import TripWireCore

public final class Monitor {
    public let store: EventStore
    public let collectors: [any Collector]
    private var ownerLock: CollectorOwnerLock?
    private var sessionStarted = false
    private var fileWatch: FileWatchSession?
    public init(store: EventStore, collectors: [any Collector]? = nil) { self.store = store; self.collectors = collectors ?? CollectorRegistry.make(storeURL: store.url) }
    deinit { release() }
    public func acquire() throws {
        guard !store.isReadOnly else { throw TripWireError.message("Collectors require an explicit writable store connection") }
        if ownerLock == nil { ownerLock = try CollectorOwnerLock(url: store.url) }
    }
    public func release() { fileWatch?.stop(); fileWatch = nil; ownerLock = nil }
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
        guard ownerLock != nil else { return }
        defer { release() }
        fileWatch?.stop()
        for var health in try store.sensors() where health.id != "file-open-events" && [.active, .degraded].contains(health.state) {
            health.state = .stopped; health.detail = "Collector owner stopped; last result: " + health.detail; try store.saveHealth(health)
        }
        try store.recordGap(CoverageGap(collector: "watchdog", start: Date(), reason: "Collector owner stopped; no continuous monitoring"))
        try store.setMetadata("openCollectorSession", "")
        sessionStarted = false
    }
}
