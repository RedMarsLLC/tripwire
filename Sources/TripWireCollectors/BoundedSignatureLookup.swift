#if os(macOS)
import Foundation
import TripWireCore

/// Security.framework may block on a process path (for example an unavailable
/// filesystem). Limit outstanding lookups and caller wait time. Timed-out work
/// retains its slot until it actually returns; retries cannot grow a thread queue.
final class BoundedSignatureLookup: @unchecked Sendable {
    static let shared = BoundedSignatureLookup()
    private let slots: DispatchSemaphore
    private let operation: @Sendable (String) -> ProcessIdentity
    init(limit: Int = 2, operation: @escaping @Sendable (String) -> ProcessIdentity = { Signature.identity($0) }) {
        slots = DispatchSemaphore(value: max(1, limit)); self.operation = operation
    }
    func identity(_ path: String, timeout: TimeInterval) -> ProcessIdentity {
        guard timeout > 0, slots.wait(timeout: .now()) == .success else { return Self.unknown(path) }
        let result = SignatureResult(), completed = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .utility).async { [self] in
            result.set(operation(path)); slots.signal(); completed.signal()
        }
        guard completed.wait(timeout: .now() + timeout) == .success, let value = result.get() else { return Self.unknown(path) }
        return value
    }
    static func unknown(_ path: String) -> ProcessIdentity {
        ProcessIdentity(executablePath: path, signatureStatus: "UNKNOWN (signing lookup exceeded its time or concurrency budget)")
    }
}
private final class SignatureResult: @unchecked Sendable {
    private let lock = NSLock()
    private var value: ProcessIdentity?
    func set(_ value: ProcessIdentity) { lock.lock(); self.value = value; lock.unlock() }
    func get() -> ProcessIdentity? { lock.lock(); defer { lock.unlock() }; return value }
}
#endif
