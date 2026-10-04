import XCTest
import Foundation
@testable import TripWireCore

final class RiskReviewTests: XCTestCase {
    private var target: String { HostPlatform.current == .windows ? "C:/fixture/private" : "/fixture/private" }
    private func fileSample(pid: Int32 = 21) -> CollectorSnapshot {
        let path = target + "/test-file"
        let row = Observation(key: "test-\(pid)", eventClass: .file, component: path, attributes: ["path": path, "associatedApp": "TEST AI", "associationBasis": "TEST ONLY"], process: ProcessIdentity(pid: pid, uid: 1000, launchTime: Date(timeIntervalSince1970: 10)), confidence: .moderate)
        return CollectorSnapshot(descriptor: SensorDescriptor("ai-open-files", "TEST ONLY", source: "TEST ONLY", monitors: "Fixture"), observations: [row], state: .degraded, visibility: .limited, detail: "TEST ONLY")
    }
    func testCorrectionsPersistPreserveEvidenceAndDoNotSuppressFutureAlerts() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("tripwire-review-test-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try EventStore(url: root.appendingPathComponent("events.sqlite"))
        let rule = TripwireRule(name: "TEST ONLY", path: target, kind: .folder)
        try store.saveTripwire(rule); try store.ingest(fileSample())
        let finding = try XCTUnwrap(store.findings().first), original = try JSONEncoder.stable.encode(finding), events = try store.events()
        XCTAssertEqual(try StoreView(store: store).riskCounts[.high], 1)
        try store.reviewFinding(id: finding.id, level: .low, status: .expected, reason: "Test operator authorized this activity", expectedReviewID: nil)
        let read = try EventStore(url: store.url, access: .readOnly), view = try StoreView(store: read)
        XCTAssertEqual(view.riskCounts.values.reduce(0,+), 0); XCTAssertEqual(view.assessment(for: finding).status, .expected)
        XCTAssertEqual(try JSONEncoder.stable.encode(XCTUnwrap(read.findings().first)), original)
        XCTAssertEqual(try JSONEncoder.stable.encode(read.events()), try JSONEncoder.stable.encode(events))
        XCTAssertThrowsError(try read.reviewFinding(id: finding.id, level: .critical, status: .open, reason: "Read only", expectedReviewID: view.findingReviews.first?.id))
        XCTAssertThrowsError(try store.reviewFinding(id: finding.id, level: .critical, status: .open, reason: "Stale draft", expectedReviewID: nil))
        XCTAssertEqual(try store.findingReviews().count, 1)
        try store.reviewFinding(id: finding.id, level: .critical, status: .open, reason: "Reopened after reviewing the evidence", expectedReviewID: view.findingReviews.first?.id)
        let reopened = try StoreView(store: store)
        XCTAssertEqual(reopened.riskCounts[.critical], 1); XCTAssertEqual(reopened.findingReviews.count, 2)
        XCTAssertEqual(reopened.findingReviews.first?.previousStatus, .expected)
        XCTAssertEqual(reopened.findingReviews.first?.suggestedLevel, .high)
        try store.ingest(fileSample(pid: 99))
        XCTAssertEqual(try StoreView(store: store).riskCounts[.high], 1, "New observations produce separate open alerts despite earlier review")
        for reason in ["", " \n", String(repeating: "x", count: 501), "bad\u{001b}input"] {
            XCTAssertThrowsError(try store.reviewFinding(id: finding.id, level: .low, status: .falsePositive, reason: reason, expectedReviewID: reopened.findingReviews.first?.id))
        }
        XCTAssertEqual(try store.findingReviews().count, 2)
    }
    func testUnknownConfidenceIsNotAssignedAnAutomaticRisk() {
        let finding = Finding(timestamp: Date(), title: "TEST ONLY", whatHappened: "Fixture", whyFlagged: "Fixture", component: "Fixture", eventIDs: [], baselineDifference: "Fixture", confidence: .unknown, severity: .elevated, limitations: ["TEST ONLY"], suggestedInvestigation: [], ruleID: "fixture")
        XCTAssertEqual(RiskLevel.suggested(for: finding), .unassessed)
    }
    func testClearQueuePreservesEvidenceAndRiskAndOnlyClearsConfirmedFindings() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("tripwire-clear-test-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try EventStore(url: root.appendingPathComponent("events.sqlite"))
        let rule = TripwireRule(name: "TEST ONLY", path: target, kind: .folder)
        try store.saveTripwire(rule); try store.ingest(fileSample())
        let finding = try XCTUnwrap(store.findings().first)
        try store.reviewFinding(id: finding.id, level: .critical, status: .open, reason: "TEST priority", expectedReviewID: nil)
        let revision = try XCTUnwrap(store.findingReviews().first?.id)
        let targets = [FindingReviewTarget(findingID: finding.id, expectedReviewID: revision)]
        // This event arrives after the UI freezes its confirmation selection.
        try store.ingest(fileSample(pid: 99))
        let originals = try JSONEncoder.stable.encode(store.findings()), events = try JSONEncoder.stable.encode(store.events())
        XCTAssertEqual(try store.clearFindingQueue(targets), 1)
        let reader = try EventStore(url: store.url, access: .readOnly), view = try StoreView(store: reader)
        XCTAssertEqual(view.assessment(for: finding).status, .cleared)
        XCTAssertEqual(view.assessment(for: finding).level, .critical)
        XCTAssertEqual(view.riskCounts[.critical], 0)
        XCTAssertEqual(view.riskCounts[.high], 1, "New arrivals must remain open")
        XCTAssertEqual(try JSONEncoder.stable.encode(reader.findings()), originals)
        XCTAssertEqual(try JSONEncoder.stable.encode(reader.events()), events)
        XCTAssertTrue(try XCTUnwrap(reader.tripwireRules().first).enabled)
        let cleared = try XCTUnwrap(view.findingReviews.first)
        XCTAssertEqual(cleared.previousStatus, .open); XCTAssertEqual(cleared.previousLevel, .critical)
        try store.reviewFinding(id: finding.id, level: .critical, status: .open, reason: "TEST undo clear", expectedReviewID: cleared.id)
        XCTAssertEqual(try StoreView(store: reader).riskCounts[.critical], 1)
        try store.ingest(fileSample(pid: 100))
        XCTAssertEqual(try StoreView(store: reader).riskCounts[.high], 2, "Clearing must not suppress future alerts")
    }
    func testClearQueueRejectsStaleMissingDuplicateAndReadOnlySelectionsWithoutPartialWrites() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("tripwire-clear-conflict-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try EventStore(url: root.appendingPathComponent("events.sqlite"))
        try store.saveTripwire(TripwireRule(name: "TEST ONLY", path: target, kind: .folder))
        try store.ingest(fileSample()); try store.ingest(fileSample(pid: 22))
        let findings = try store.findings()
        XCTAssertEqual(findings.count, 2)
        let first = FindingReviewTarget(findingID: findings[0].id, expectedReviewID: nil)
        let stale = FindingReviewTarget(findingID: findings[1].id, expectedReviewID: nil)
        try store.reviewFinding(id: stale.findingID, level: .low, status: .expected, reason: "TEST concurrent review", expectedReviewID: nil)
        for targets in [[first, stale], [first, FindingReviewTarget(findingID: "missing", expectedReviewID: nil)], [first, first], []] {
            XCTAssertThrowsError(try store.clearFindingQueue(targets))
            XCTAssertEqual(try store.findingReviews().count, 1, "Any failure must roll back the entire batch")
            XCTAssertEqual(try StoreView(store: store).assessment(for: findings[0]).status, .open)
        }
        let reader = try EventStore(url: store.url, access: .readOnly)
        XCTAssertThrowsError(try reader.clearFindingQueue([first]))
        XCTAssertEqual(try store.findingReviews().count, 1)
    }
}
