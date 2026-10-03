import Foundation
import CryptoKit
import TripWireCore

public struct SelfIntegrityCollector: Collector {
    public let descriptor = SensorDescriptor("watchdog-integrity", "Watchdog executable / store metadata", source: "Foundation, no-follow file reads, CryptoKit SHA-256, Security signing metadata", monitors: "On-disk executable hash and event-store ownership/mode", limitations: ["On-disk hash does not attest running memory or loaded libraries.", "Same-user or root compromise can alter both application and evidence; this is not tamper-proof attestation.", "No independent external watchdog is installed. Termination is inferred from missing heartbeats/restart gaps."])
    public let storeURL: URL
    public init(storeURL: URL) { self.storeURL = storeURL }
    public func collect() async -> CollectorSnapshot {
        var observations: [Observation] = [], errors = 0
        if let executable = Bundle.main.executableURL {
            do {
                var attrs = try SafeFile.metadata(executable, hash: false)
                let fd = open(executable.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
                guard fd >= 0 else { throw TripWireError.message("Own executable unreadable") }
                defer { close(fd) }
                var before = stat(), after = stat()
                guard fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFREG, before.st_size <= 128 * 1024 * 1024 else { throw TripWireError.message("Own executable hash scope unavailable") }
                var hasher = SHA256(), buffer = [UInt8](repeating: 0, count: 65536), total = 0
                while true {
                    let count = Darwin.read(fd, &buffer, buffer.count)
                    guard count >= 0 else { throw TripWireError.message("Own executable read failed") }
                    if count == 0 { break }
                    total += count
                    guard total <= 128 * 1024 * 1024 else { throw TripWireError.message("Own executable exceeded limit") }
                    hasher.update(data: Data(buffer.prefix(count)))
                }
                guard fstat(fd, &after) == 0, before.st_size == after.st_size, before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec, before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec else { throw TripWireError.message("Own executable changed during hashing") }
                attrs["sha256"] = hasher.finalize().map { String(format: "%02x", $0) }.joined()
                let signature = Signature.identity(executable.path)
                attrs["teamID"] = signature.teamID ?? "UNKNOWN"; attrs["signature"] = signature.signatureStatus ?? "UNKNOWN"
                observations.append(Observation(key: executable.path, eventClass: .health, component: "Watchdog executable on disk", attributes: attrs, limitations: descriptor.limitations))
            } catch { errors += 1 }
        } else { errors += 1 }
        do {
            let attrs = try SafeFile.metadata(storeURL, hash: false).filter { ["path", "ownerUID", "groupGID", "mode", "type"].contains($0.key) }
            observations.append(Observation(key: "event-store", eventClass: .health, component: "Event-store ownership and permissions", attributes: attrs, limitations: descriptor.limitations))
        } catch { errors += 1 }
        return CollectorSnapshot(descriptor: descriptor, observations: observations, complete: errors == 0, absenceReliable: false, state: errors == 0 ? .active : .error, visibility: .limited, detail: "\(observations.count) integrity observations; \(errors) unavailable checks. No tamper-proof attestation.")
    }
}
