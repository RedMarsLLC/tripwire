import Foundation
import TripWireCore

/// Presentation acknowledgement only; never modifies findings or detection.
struct AlertBannerState {
    private var dismissed = Set<String>()
    private var repeatedUntilQuiet: [[String]: TimeInterval] = [:]
    private let quietInterval: TimeInterval = 30
    private func group(_ finding: Finding) -> [String] {
        // Includes the action/process description and rule revision so a new
        // actor, operation, path or policy can still surface immediately.
        [finding.ruleID, finding.component, finding.whatHappened, finding.baselineDifference, finding.severity.rawValue]
    }
    mutating func dismiss(_ pending: [Finding], now: TimeInterval = ProcessInfo.processInfo.systemUptime) {
        dismissed.formUnion(pending.map(\.id))
        for finding in pending { repeatedUntilQuiet[group(finding)] = now }
    }
    mutating func next(_ pending: [Finding], now: TimeInterval = ProcessInfo.processInfo.systemUptime) -> Finding? {
        repeatedUntilQuiet = repeatedUntilQuiet.filter { now - $0.value < quietInterval }
        var candidate: Finding?
        for finding in pending where !dismissed.contains(finding.id) {
            let key = group(finding)
            if repeatedUntilQuiet[key] != nil {
                dismissed.insert(finding.id); repeatedUntilQuiet[key] = now
            } else if candidate == nil { candidate = finding }
        }
        return candidate
    }
}
