import Foundation
import TripWireCore

enum MetricFocus: Equatable {
    case hostCPU, swap, appCPU(String?), reports(String?)
    var title: String {
        switch self {
        case .hostCPU: return "Host CPU"
        case .swap: return "Swap activity"
        case .appCPU: return "AI app CPU"
        case .reports: return "Agent action reports"
        }
    }
}

struct MetricCapture {
    var date: Date
    var resources: ResourceMetrics
    var apps: AppResourceMetrics
    var hooks: AgentActivityView
    var hookHistory: AgentActivityHistory
}

struct MetricInspection: Identifiable {
    let id = UUID()
    var focus: MetricFocus
    var interval: DateInterval
    var capture: MetricCapture
    var primary: [MetricPoint] {
        switch focus {
        case .hostCPU: return capture.resources.cpu.points
        case .swap: return capture.resources.swapIn.points
        case .appCPU(let id): return id.map { capture.apps.perApp[$0]?.points ?? [] } ?? capture.apps.history.points
        case .reports(let id): return capture.hookHistory.points(for: id)
        }
    }
    var selectedApps: [AppResourceFrame] {
        capture.apps.frames.filter { interval.contains($0.timestamp) }
    }
}

enum MetricSelection {
    /// Freeze the chart's clock at mouse-down. A click inspects a four-second
    /// neighborhood; a drag selects its actual time boundaries, in either direction.
    static func interval(from start: Double, to end: Double, width: Double, endingAt date: Date) -> DateInterval {
        let width = max(1, width)
        func time(_ x: Double) -> Date { date.addingTimeInterval(-60 + 60 * min(1, max(0, x / width))) }
        let first = time(start), last = time(end)
        if abs(end - start) < 3 {
            return DateInterval(start: max(date.addingTimeInterval(-60), first.addingTimeInterval(-2)), end: min(date, first.addingTimeInterval(2)))
        }
        return DateInterval(start: min(first, last), end: max(first, last))
    }
    static func selected(_ points: [MetricPoint], in interval: DateInterval) -> [MetricPoint] {
        points.filter { interval.contains($0.timestamp) }
    }
    static func gaps(_ points: [MetricPoint], in interval: DateInterval) -> [String] {
        var reasons = Set(selected(points, in: interval).filter { $0.value == nil }.map { $0.reason ?? "No valid measurement" })
        let valid = selected(points, in: interval).filter { $0.value != nil }
        if valid.isEmpty { reasons.insert("No measured values in this selection; activity is unknown") }
        if let first = valid.first, first.timestamp.timeIntervalSince(interval.start) > ResourceMetrics.staleAfter { reasons.insert("Start of selection has no recent sample") }
        if let last = valid.last, interval.end.timeIntervalSince(last.timestamp) > ResourceMetrics.staleAfter { reasons.insert("End of selection has no recent sample") }
        for (a, b) in zip(valid, valid.dropFirst()) where b.timestamp.timeIntervalSince(a.timestamp) > ResourceMetrics.staleAfter {
            reasons.insert("Samples more than 3 seconds apart; missing work is unknown")
        }
        // A selection inside a long gap still needs its recorded interruption reason.
        if valid.isEmpty, let preceding = points.last(where: { $0.timestamp < interval.start }), preceding.value == nil, let reason = preceding.reason { reasons.insert(reason) }
        return reasons.sorted()
    }
}
