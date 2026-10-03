import Foundation

public struct AIApplication: Sendable, Equatable, Identifiable {
    public var id: String
    public var name: String
    public var bundlePath: String
    public var pid: Int32
    public init(id: String, name: String, bundlePath: String, pid: Int32) {
        self.id = id; self.name = name; self.bundlePath = bundlePath; self.pid = pid
    }
}

public struct AppProcessCounter: Sendable {
    public var appID: String
    public var pid: Int32
    public var started: UInt64
    public var cpuTicks: UInt64
    public var footprint: UInt64
    public var key: String { "\(pid):\(started)" }
    public init(appID: String, pid: Int32, started: UInt64, cpuTicks: UInt64, footprint: UInt64) {
        self.appID = appID; self.pid = pid; self.started = started; self.cpuTicks = cpuTicks; self.footprint = footprint
    }
}

public struct AppResourceSample: Sendable {
    public var timestamp: Date
    public var uptime: TimeInterval
    public var secondsPerTick: Double
    public var coreCount: Int
    public var apps: [AIApplication]
    public var processes: [AppProcessCounter]
    public var limited: Bool
    public var error: String?
    public init(timestamp: Date = Date(), uptime: TimeInterval = ProcessInfo.processInfo.systemUptime,
                secondsPerTick: Double, coreCount: Int, apps: [AIApplication], processes: [AppProcessCounter], limited: Bool = false, error: String? = nil) {
        self.timestamp = timestamp; self.uptime = uptime; self.secondsPerTick = secondsPerTick; self.coreCount = coreCount
        self.apps = apps; self.processes = processes; self.limited = limited; self.error = error
    }
}

public struct AppResourceReading: Sendable, Identifiable {
    public var id: String
    public var name: String
    public var cpuPercent: Double?
    public var memoryBytes: Double?
    public var processCount: Int
    public var limited: Bool
}

public struct AppResourceFrame: Sendable {
    public var timestamp: Date
    public var readings: [AppResourceReading]
}

/// CPU is the measured share of all host cores, not an inference about prompts,
/// model execution, tokens or remote servers. Resource history is transient.
public struct AppResourceMetrics: Sendable {
    public private(set) var readings: [AppResourceReading] = []
    public private(set) var history = MetricHistory()
    public private(set) var perApp: [String: MetricHistory] = [:]
    public private(set) var frames: [AppResourceFrame] = []
    public private(set) var lastSample: Date?
    public private(set) var error: String?
    public private(set) var limited = false
    private var previous: AppResourceSample?
    public init() {}
    public var totalCPU: Double? {
        let values = readings.compactMap(\.cpuPercent)
        return values.isEmpty ? nil : values.reduce(0, +)
    }
    public var totalMemory: Double? {
        let values = readings.compactMap(\.memoryBytes)
        return values.isEmpty ? nil : values.reduce(0, +)
    }
    public func isFresh(at date: Date) -> Bool {
        lastSample.map { (0...ResourceMetrics.staleAfter).contains(date.timeIntervalSince($0)) } ?? false
    }
    public mutating func ingest(_ sample: AppResourceSample) {
        defer { previous = sample }
        lastSample = sample.timestamp; error = sample.error; limited = sample.limited
        let elapsed = previous.map { sample.uptime - $0.uptime } ?? 0
        let continuous = previous.map { old in
            old.error == nil && sample.error == nil && elapsed > 0 && elapsed <= ResourceMetrics.staleAfter &&
            abs(sample.timestamp.timeIntervalSince(old.timestamp) - elapsed) < 0.5 &&
            sample.coreCount > 0 && old.coreCount == sample.coreCount && sample.secondsPerTick > 0 &&
            sample.secondsPerTick.isFinite && sample.secondsPerTick == old.secondsPerTick
        } ?? false
        let prior = Dictionary((previous?.processes ?? []).map { ($0.key, $0) }, uniquingKeysWith: { first, _ in first })
        readings = sample.error == nil ? sample.apps.map { app in
            let processes = sample.processes.filter { $0.appID == app.id }
            let priorKeys = Set((previous?.processes ?? []).filter { $0.appID == app.id }.map(\.key))
            let keys = Set(processes.map(\.key))
            var incomplete = sample.limited || previous?.limited == true || keys != priorKeys
            let deltas: [Double] = continuous ? processes.compactMap { process in
                guard let old = prior[process.key], old.appID == process.appID, process.cpuTicks >= old.cpuTicks else {
                    incomplete = true; return nil
                }
                return Double(process.cpuTicks - old.cpuTicks) * sample.secondsPerTick
            } : []
            let value = deltas.isEmpty ? nil : 100 * deltas.reduce(0, +) / elapsed / Double(sample.coreCount)
            let validCPU = value.flatMap { $0.isFinite && (0...100).contains($0) ? $0 : nil }
            return AppResourceReading(id: app.id, name: app.name, cpuPercent: validCPU,
                                      memoryBytes: processes.isEmpty ? nil : processes.reduce(0) { $0 + Double($1.footprint) },
                                      processCount: processes.count, limited: incomplete || processes.isEmpty || validCPU == nil)
        } : []
        limited = limited || readings.contains { $0.limited || $0.cpuPercent == nil }
        let reason = sample.error ?? (sample.processes.isEmpty ? "No app process measured" : !continuous ? "Waiting for continuous samples; opening, pause or sampling delay" : "Process counters unavailable or changed")
        history.append(MetricPoint(timestamp: sample.timestamp, value: totalCPU, reason: totalCPU == nil ? reason : nil))
        if let last = frames.last, sample.timestamp < last.timestamp { frames.removeAll(); perApp.removeAll() }
        frames.append(AppResourceFrame(timestamp: sample.timestamp, readings: readings))
        frames.removeAll { sample.timestamp.timeIntervalSince($0.timestamp) > MetricHistory.window }
        if frames.count > MetricHistory.maximumCount { frames.removeFirst(frames.count - MetricHistory.maximumCount) }
        let ids = Set(readings.map(\.id))
        let retainedIDs = Set(frames.flatMap { $0.readings.map(\.id) })
        perApp = perApp.filter { retainedIDs.contains($0.key) }
        for id in Array(perApp.keys) where !ids.contains(id) {
            perApp[id]?.append(MetricPoint(timestamp: sample.timestamp, value: nil, reason: "App no longer observed"))
        }
        for reading in readings {
            var points = perApp[reading.id] ?? MetricHistory()
            points.append(MetricPoint(timestamp: sample.timestamp, value: reading.cpuPercent, reason: reading.cpuPercent == nil ? reason : nil))
            perApp[reading.id] = points
        }
    }
    public mutating func interrupt(at date: Date, reason: String = "App resource sampling paused") {
        previous = nil; readings = []; lastSample = nil
        history.append(MetricPoint(timestamp: date, value: nil, reason: reason))
        for key in Array(perApp.keys) { perApp[key]?.append(MetricPoint(timestamp: date, value: nil, reason: reason)) }
    }
}
