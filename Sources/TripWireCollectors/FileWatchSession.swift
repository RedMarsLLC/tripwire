import Foundation
import TripWireCore

/// A bounded snapshot loop independent of slow system inventories. The gate makes
/// stop synchronous: an in-flight libproc sample cannot write after stop returns.
final class FileWatchSession {
    private let gate = NSLock()
    private var enabled = true
    private var failure: String?
    private var lastReport: Date?
    private var task: Task<Void, Never>?
    private let store: EventStore

    init(store: EventStore, collector: any Collector, interval: UInt64 = 2_000_000_000) {
        self.store = store
        task = Task.detached(priority: .utility) { [weak self] in
            while !Task.isCancelled {
                let snapshot = await collector.collect()
                guard !Task.isCancelled, self?.commit(snapshot) == true else { break }
                do { try await Task.sleep(nanoseconds: interval) } catch { break }
            }
        }
    }
    private func commit(_ snapshot: CollectorSnapshot) -> Bool {
        gate.lock(); defer { gate.unlock() }
        guard enabled else { return false }
        do {
            if let prior = lastReport, snapshot.timestamp.timeIntervalSince(prior) > 10 {
                try store.recordGap(CoverageGap(collector: AIFileAccessCollector.id, start: prior, end: snapshot.timestamp,
                    reason: "Open-file check interval exceeded 10 seconds; sleep or scheduling delay may have interrupted snapshots. Missed access count UNKNOWN."))
            }
            try store.ingest(snapshot); lastReport = snapshot.timestamp; return true
        }
        catch { failure = "File watch could not save evidence: \(error)"; enabled = false; return false }
    }
    func check() throws {
        gate.lock(); defer { gate.unlock() }
        if let failure { throw TripWireError.message(failure) }
    }
    func stop() {
        gate.lock(); enabled = false; gate.unlock()
        task?.cancel()
    }
    deinit { task?.cancel() }
}
