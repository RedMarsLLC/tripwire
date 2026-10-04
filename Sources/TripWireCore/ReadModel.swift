import Foundation

public struct StoreView {
    public var sensors: [SensorHealth]
    public var events: [EvidenceEvent]
    public var findings: [Finding]
    public var inventory: [InventoryRecord]
    public var gaps: [CoverageGap]
    public var databaseHealth: String
    public var sampledAt: String
    public var tripwires: [TripwireRule]
    public var findingReviews: [FindingReview]
    private var latestReviewByFinding: [String: FindingReview]
    public func assessment(for finding: Finding) -> FindingAssessment { FindingAssessment(finding: finding, reviews: latestReviewByFinding[finding.id].map { [$0] } ?? []) }
    public var openFindings: [Finding] { findings.filter { assessment(for: $0).status == .open } }
    public var riskCounts: [RiskLevel: Int] {
        var counts = Dictionary(uniqueKeysWithValues: RiskLevel.allCases.map { ($0, 0) })
        for finding in findings { let review = assessment(for: finding); if review.status == .open { counts[review.level, default: 0] += 1 } }
        return counts
    }
    public init(store: EventStore) throws {
        let result = try store.readSnapshot {
            (try store.sensors().map { $0.effective(staleAfter: ["file-open-events", "ai-open-files"].contains($0.id) ? 10 : 90) }, try store.events(limit: 200), try store.findings(), try store.inventory(), try store.gaps(), try store.integrityCheck(), try store.metadata("lastCompletedSample"), try store.tripwireRules(), try store.findingReviews())
        }
        sensors = result.0; events = result.1; findings = result.2; inventory = result.3; gaps = result.4; databaseHealth = result.5
        sampledAt = result.6.flatMap(Double.init).map { TimeText.iso(Date(timeIntervalSince1970: $0)) } ?? "NEVER"
        tripwires = result.7
        findingReviews = result.8
        latestReviewByFinding = Dictionary(findingReviews.map { ($0.findingID, $0) }, uniquingKeysWith: { first, _ in first })
    }
    public var changes: Int { events.filter { ["NEW", "CHANGED", "REMOVED"].contains($0.eventType) }.count }
    public var unknowns: Int { inventory.filter { $0.baselineStatus == .unknown || $0.observation.attributes.values.contains(where: { $0.hasPrefix("UNKNOWN") || $0.hasPrefix("NOT OBSERVABLE") || $0.hasPrefix("UNAVAILABLE") }) }.count }
    public var coverage: String {
        guard !sensors.isEmpty else { return "UNKNOWN — NO CHECKS RECORDED" }
        let current = sensors.map { $0.effective() }
        let live = current.filter { [.active, .degraded].contains($0.state) && [.available, .limited].contains($0.visibility) }.count
        let failed = current.filter { [.error, .dataLossDetected].contains($0.state) || ($0.state == .permissionMissing && $0.visibility != .unavailable) }.count
        if failed > 0 { return "\(failed) CHECK\(failed == 1 ? "" : "S") FAILED — SEE SENSOR STATUS" }
        if live == 0 { return current.contains { $0.state == .stopped } ? "CHECKS STOPPED — START MONITORING" : "NO LIVE CHECKS — SEE SENSOR STATUS" }
        let unavailable = current.filter { $0.visibility == .unavailable || $0.state == .unsupported }.count
        return "\(live) CHECKS REPORTING · \(unavailable) UNAVAILABLE"
    }
}
public enum Explain {
    public static func text(_ finding: Finding, events: [EvidenceEvent]) -> String {
        let related = events.filter { finding.eventIDs.contains($0.id) }.sorted { $0.timestamp < $1.timestamp }
        let timeline = related.map { "\(TimeText.iso($0.timestamp))  \($0.observation.eventClass.rawValue)  \($0.eventType)  \($0.observation.component) [\($0.id)]" }.joined(separator: "\n")
        let evidence = related.map { e in
            "EVENT \(e.id) / SOURCE \(e.sourceCollector)\n" + e.evidence.joined(separator: "\n") + "\n" + BaselineEngine.differences(e.previousState, e.currentState).joined(separator: "\n")
        }.joined(separator: "\n\n")
        let associations = related.compactMap { event -> String? in
            guard let app = event.observation.attributes["associatedApp"], let basis = event.observation.attributes["associationBasis"] else { return nil }
            return "\(app): \(basis)"
        }
        let attribution = associations.isEmpty ? "UNKNOWN. Nearby activity or a resource spike alone does not prove causation." : Array(Set(associations)).sorted().joined(separator: "\n") + "\nAssociation is not proof of an AI instruction, user authorization or malicious intent."
        return """
        \(finding.title.uppercased())
        ID \(finding.id)

        WHAT HAPPENED
        \(finding.whatHappened)

        WHY IT WAS FLAGGED
        \(finding.whyFlagged)

        RESPONSIBLE AGENT
        \(attribution)

        PROCESS / COMPONENT
        \(finding.component)

        HOW WAS IT ACCESSED?
        \(related.compactMap(AccessContext.text).joined(separator: "\n\n"))

        TIMELINE (observation times)
        \(timeline.isEmpty ? "Evidence unavailable in this view" : timeline)

        SUPPORTING EVIDENCE
        \(evidence)

        BASELINE DIFFERENCE
        \(finding.baselineDifference)

        OBSERVATION CONFIDENCE
        \(finding.confidence.rawValue): confidence in the observation, not malicious intent.
        Intent: \(finding.intent)

        VISIBILITY LIMITATIONS
        \(finding.limitations.joined(separator: "\n"))

        SUGGESTED INVESTIGATION
        \(finding.suggestedInvestigation.joined(separator: "\n"))
        """
    }
}
