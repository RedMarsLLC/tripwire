import Foundation

/// Aggregate ticks across all CPUs. Percentages describe the whole host, 0...100.
public struct CPUTicks: Equatable, Sendable {
    public var user: UInt64, system: UInt64, idle: UInt64, nice: UInt64
    public init(user: UInt64, system: UInt64, idle: UInt64, nice: UInt64) {
        self.user = user; self.system = system; self.idle = idle; self.nice = nice
    }
    public func utilization(since old: CPUTicks) -> Double? {
        // Counter wrap/reset is an unknown interval, never a fabricated spike.
        let current = [user, system, idle, nice], previous = [old.user, old.system, old.idle, old.nice]
        guard zip(current, previous).allSatisfy({ $0 >= $1 }) else { return nil }
        let delta = zip(current, previous).map { Double($0 - $1) }
        let total = delta.reduce(0, +)
        guard total > 0 else { return nil }
        return 100 * (delta[0] + delta[1] + delta[3]) / total
    }
}

/// Physical RAM not in the VM free-page count. Includes reclaimable/cache pages;
/// deliberately not named Activity Monitor's “Memory Used” or memory pressure.
public struct RAMUsage: Equatable, Sendable {
    public let occupiedBytes: UInt64
    public let totalBytes: UInt64
    public let fileBackedBytes: UInt64?
    public let compressedBytes: UInt64?
    public let wiredBytes: UInt64?
    public let usedEstimateBytes: UInt64?
    public var percent: Double { 100 * Double(occupiedBytes) / Double(totalBytes) }
    public init?(totalBytes: UInt64, freePages: UInt64, pageSize: UInt64, fileBackedPages: UInt64? = nil, compressedPages: UInt64? = nil, wiredPages: UInt64? = nil, anonymousPages: UInt64? = nil, purgeablePages: UInt64? = nil) {
        let (freeBytes, overflow) = freePages.multipliedReportingOverflow(by: pageSize)
        guard totalBytes > 0, pageSize > 0, !overflow, freeBytes <= totalBytes else { return nil }
        self.totalBytes = totalBytes; occupiedBytes = totalBytes - freeBytes
        func bytes(_ pages: UInt64?) -> UInt64? {
            guard let pages else { return nil }
            let (value, overflow) = pages.multipliedReportingOverflow(by: pageSize)
            return overflow || value > totalBytes ? nil : value
        }
        fileBackedBytes = bytes(fileBackedPages); compressedBytes = bytes(compressedPages); wiredBytes = bytes(wiredPages)
        // Excludes file-backed cache and purgeable anonymous pages. This is an
        // estimate from public VM counters, not Activity Monitor's private accounting.
        if let anonymous = bytes(anonymousPages), let purgeable = bytes(purgeablePages),
           let wired = wiredBytes, let compressed = compressedBytes, anonymous >= purgeable {
            let (resident, overflow1) = (anonymous - purgeable).addingReportingOverflow(wired)
            let (used, overflow2) = resident.addingReportingOverflow(compressed)
            usedEstimateBytes = !overflow1 && !overflow2 && used <= totalBytes ? used : nil
        } else { usedEstimateBytes = nil }
    }
    public var breakdown: String {
        func gib(_ value: UInt64?) -> String { value.map { String(format: "%.2f GiB", Double($0) / 1_073_741_824) } ?? "UNKNOWN" }
        return "File-backed pages: \(gib(fileBackedBytes)); compressed physical RAM: \(gib(compressedBytes)); wired RAM: \(gib(wiredBytes))"
    }
}

public enum MemoryPressure: String, Sendable { case unknown = "UNKNOWN", normal = "NORMAL", warning = "ELEVATED", critical = "CRITICAL" }

public struct MemoryPressureReading: Equatable, Sendable {
    public var state: MemoryPressure
    public var detail: String
    public init(state: MemoryPressure, detail: String) { self.state = state; self.detail = detail }
}

public struct SwapCounters: Sendable {
    public let pageIns: UInt64, pageOuts: UInt64, pageSize: UInt64
    public init(pageIns: UInt64, pageOuts: UInt64, pageSize: UInt64) {
        self.pageIns = pageIns; self.pageOuts = pageOuts; self.pageSize = pageSize
    }
    public func rate(since old: Self, seconds: TimeInterval) -> SwapRate? {
        guard seconds > 0, seconds <= ResourceMetrics.staleAfter, pageSize > 0,
              pageSize == old.pageSize, pageIns >= old.pageIns, pageOuts >= old.pageOuts else { return nil }
        return SwapRate(inMiB: Double(pageIns - old.pageIns) * Double(pageSize) / seconds / 1_048_576,
                        outMiB: Double(pageOuts - old.pageOuts) * Double(pageSize) / seconds / 1_048_576)
    }
}
public struct SwapRate: Equatable, Sendable { public let inMiB: Double, outMiB: Double }
public struct PressurePoint: Equatable, Sendable { public let timestamp: Date; public let state: MemoryPressure }

public struct HostResourceCounters: Sendable {
    public var timestamp: Date
    public var uptime: TimeInterval
    public var cpu: CPUTicks?
    public var ram: RAMUsage?
    public var swap: SwapCounters?
    public var pressure: MemoryPressureReading?
    public init(timestamp: Date, uptime: TimeInterval, cpu: CPUTicks?, ram: RAMUsage?, swap: SwapCounters? = nil, pressure: MemoryPressureReading? = nil) {
        self.timestamp = timestamp; self.uptime = uptime; self.cpu = cpu; self.ram = ram; self.swap = swap; self.pressure = pressure
    }
}

public struct MetricPoint: Equatable, Sendable {
    public var timestamp: Date
    public var value: Double?
    public var reason: String?
    public init(timestamp: Date, value: Double?, reason: String? = nil) { self.timestamp = timestamp; self.value = value; self.reason = reason }
}

/// Time bounded AND count bounded. A nil point breaks a trace; it is not zero.
public struct MetricHistory: Sendable {
    public static let window: TimeInterval = 60
    public static let maximumCount = 64
    public private(set) var points: [MetricPoint] = []
    public init() {}
    public mutating func append(_ point: MetricPoint) {
        if let last = points.last, point.timestamp < last.timestamp { points.removeAll() }
        if points.last?.timestamp == point.timestamp { points.removeLast() }
        points.append(MetricPoint(timestamp: point.timestamp, value: point.value.flatMap { $0.isFinite ? $0 : nil }, reason: point.reason))
        points.removeAll { $0.timestamp < point.timestamp.addingTimeInterval(-Self.window) }
        if points.count > Self.maximumCount { points.removeFirst(points.count - Self.maximumCount) }
    }
}

public struct ResourceMetrics: Sendable {
    public static let staleAfter: TimeInterval = 3
    public private(set) var cpu = MetricHistory()
    public private(set) var ram = MetricHistory()
    public private(set) var usedRAMGiB = MetricHistory()
    public private(set) var latestRAM: RAMUsage?
    public private(set) var swapRate: SwapRate?
    public private(set) var swapIn = MetricHistory()
    public private(set) var swapOut = MetricHistory()
    public private(set) var pressureHistory: [PressurePoint] = []
    public private(set) var pressure: MemoryPressure = .unknown
    public private(set) var pressureObservedAt: Date?
    public private(set) var pressureDetail = "Waiting for the first memory-pressure reading."
    public private(set) var lastSample: Date?
    public private(set) var gapReason: String? = "Waiting for two CPU samples"
    private var previous: HostResourceCounters?
    public init() {}

    /// Returns false on a time discontinuity so the owner can reset its pressure
    /// source. Missing CPU and RAM data remain independent.
    @discardableResult public mutating func ingest(_ counters: HostResourceCounters) -> Bool {
        let wall = previous.map { counters.timestamp.timeIntervalSince($0.timestamp) }
        let elapsed = previous.map { counters.uptime - $0.uptime }
        let continuous = wall.map { $0 > 0 && $0 <= Self.staleAfter } == true &&
            elapsed.map { $0 > 0 && $0 <= Self.staleAfter } == true && abs((wall ?? 0) - (elapsed ?? 0)) < 0.5
        let utilization = continuous ? previous?.cpu.flatMap { counters.cpu?.utilization(since: $0) } : nil
        if previous != nil && !continuous {
            pressure = .unknown; pressureObservedAt = nil
            pressureDetail = "Sampling was interrupted; waiting for a fresh pressure reading."
            gapReason = "Sampling gap / clock change; CPU interval unknown"
        } else { gapReason = utilization == nil ? "CPU interval unavailable" : nil }
        swapRate = continuous ? previous?.swap.flatMap { counters.swap?.rate(since: $0, seconds: elapsed ?? 0) } : nil
        let intervalReason = previous == nil ? "Waiting for two samples after opening or resuming" : !continuous ? "Samples delayed or clock changed" : "Counter unavailable or reset"
        swapIn.append(MetricPoint(timestamp: counters.timestamp, value: swapRate?.inMiB, reason: swapRate == nil ? intervalReason : nil))
        swapOut.append(MetricPoint(timestamp: counters.timestamp, value: swapRate?.outMiB, reason: swapRate == nil ? intervalReason : nil))
        if let reading = counters.pressure {
            pressure = reading.state; pressureDetail = reading.detail
            pressureObservedAt = reading.state == .unknown ? nil : counters.timestamp
        }
        pressureHistory.append(PressurePoint(timestamp: counters.timestamp, state: pressure))
        pressureHistory.removeAll { counters.timestamp.timeIntervalSince($0.timestamp) > 60 || $0.timestamp > counters.timestamp }
        if pressureHistory.count > 64 { pressureHistory.removeFirst(pressureHistory.count - 64) }
        cpu.append(MetricPoint(timestamp: counters.timestamp, value: utilization, reason: utilization == nil ? intervalReason : nil))
        usedRAMGiB.append(MetricPoint(timestamp: counters.timestamp, value: counters.ram?.usedEstimateBytes.map { Double($0) / 1_073_741_824 }, reason: counters.ram?.usedEstimateBytes == nil ? "RAM estimate unavailable" : nil))
        ram.append(MetricPoint(timestamp: counters.timestamp, value: counters.ram?.percent))
        latestRAM = counters.ram; lastSample = counters.timestamp; previous = counters
        return continuous
    }
    public mutating func updatePressure(_ value: MemoryPressure, at date: Date) {
        pressure = value; pressureObservedAt = date
        pressureDetail = "macOS memory-pressure change notification."
    }
    public mutating func interrupt(at date: Date, reason: String) {
        previous = nil; latestRAM = nil; lastSample = nil; swapRate = nil
        swapIn.append(MetricPoint(timestamp: date, value: nil, reason: reason)); swapOut.append(MetricPoint(timestamp: date, value: nil, reason: reason))
        pressureHistory.append(PressurePoint(timestamp: date, state: .unknown))
        if pressureHistory.count > 64 { pressureHistory.removeFirst(pressureHistory.count - 64) }
        pressure = .unknown; pressureObservedAt = nil; gapReason = reason
        pressureDetail = reason + ". Waiting for resource sampling to resume."
        cpu.append(MetricPoint(timestamp: date, value: nil, reason: reason)); ram.append(MetricPoint(timestamp: date, value: nil, reason: reason))
        usedRAMGiB.append(MetricPoint(timestamp: date, value: nil, reason: reason))
    }
    public func isFresh(at date: Date) -> Bool {
        guard let lastSample else { return false }
        return (0...Self.staleAfter).contains(date.timeIntervalSince(lastSample))
    }
}

public enum AgentActivityKind: String, CaseIterable, Codable, Sendable {
    case file = "F", process = "P", network = "N", approval = "A", tool = "T"
}

/// Reserved adapter boundary, not process-name inference. An adapter must verify
/// attribution/coverage before constructing this value and preserve the linked
/// evidence in the shared store. No such producer ships in this build.
public struct AttributedAgentActivity: Sendable {
    public let evidenceID: String
    public let timestamp: Date
    public let kind: AgentActivityKind
    public let agentID: String
    public let processInstanceKey: String
    public let attributionSource: String
    public init?(evidenceID: String, timestamp: Date, kind: AgentActivityKind, agentID: String,
                 processInstanceKey: String, attributionSource: String) {
        guard [evidenceID, agentID, processInstanceKey, attributionSource].allSatisfy({ !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }) else { return nil }
        self.evidenceID = evidenceID; self.timestamp = timestamp; self.kind = kind
        self.agentID = agentID; self.processInstanceKey = processInstanceKey; self.attributionSource = attributionSource
    }
}

public struct AgentActivityReading: Sendable {
    public var eventsPerMinute: Int?
    public var markers: [AttributedAgentActivity]
    public var status: String
    public static let unavailable = AgentActivityReading(eventsPerMinute: nil, markers: [], status: "UNAVAILABLE · NO ATTRIBUTION SOURCE")

    /// Count the observed trailing minute; never extrapolate a short interval.
    /// Zero requires an adapter's uninterrupted coverage of that entire minute.
    public static func evaluate(events: [AttributedAgentActivity], coverageStart: Date?, coverageEnd: Date?, now: Date) -> Self {
        guard let start = coverageStart, let end = coverageEnd else { return .unavailable }
        let cutoff = now.addingTimeInterval(-60)
        guard start <= cutoff, end >= now else {
            return Self(eventsPerMinute: nil, markers: [], status: "UNKNOWN · INCOMPLETE MINUTE")
        }
        var seen = Set<String>()
        let valid = events.filter { $0.timestamp > cutoff && $0.timestamp <= now && seen.insert($0.evidenceID).inserted }
            .sorted { $0.timestamp < $1.timestamp }
        return Self(eventsPerMinute: valid.count, markers: valid, status: "ATTRIBUTED / LAST 60 SECONDS")
    }
}
