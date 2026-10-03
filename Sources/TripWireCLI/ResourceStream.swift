import Foundation
import TripWireCore
import TripWireCollectors

/// A process-owned stream: an overlay may hide without restarting counters.
/// It does not start security collection, and never inserts metric fixtures.
enum ResourceStream {
    struct Frame: Encodable {
        var schemaVersion = 1
        var platform: HostPlatform
        var timestamp: String
        var cpuPercent: Double?
        var memoryUsedBytes: UInt64?
        var memoryTotalBytes: UInt64?
        var memoryDefinition: String
        var pressure: String
        var pressureDetail: String
        var limitations: [String]
    }
    static func run(once: Bool) async throws {
        var metrics = ResourceMetrics()
        metrics.ingest(HostResourceSampler.sample())
        repeat {
            try await Task.sleep(nanoseconds: 1_000_000_000)
            metrics.ingest(HostResourceSampler.sample())
            let frame = Frame(platform: .current, timestamp: TimeText.iso(metrics.lastSample), cpuPercent: metrics.cpu.points.last?.value,
                memoryUsedBytes: metrics.latestRAM?.usedEstimateBytes, memoryTotalBytes: metrics.latestRAM?.totalBytes,
                memoryDefinition: metrics.latestRAM?.definition ?? "UNKNOWN — no memory sample", pressure: metrics.pressure.rawValue, pressureDetail: metrics.pressureDetail,
                limitations: ["Host resource sampling is separate from security monitoring.", "Cloud inference, tokens, GPU usage and per-prompt attribution are not measured.", "Missing and interrupted samples are unknown, not zero.", "Linux CPU includes steal time as non-idle and iowait as idle, and may describe the host outside container quotas. Windows multi-processor-group CPU is unavailable in this adapter."])
            var data = try JSONEncoder.stable.encode(frame); data.append(10)
            try FileHandle.standardOutput.write(contentsOf: data)
            if once { return }
        } while !Task.isCancelled
    }
}
