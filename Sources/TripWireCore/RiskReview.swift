import Foundation

/// Review priority is separate from observation confidence and malicious intent.
public enum RiskLevel: String, Codable, CaseIterable, Identifiable {
    case critical, high, medium, low, unassessed
    public var id: String { rawValue }
    public var label: String { rawValue.capitalized }
    public var order: Int { Self.allCases.firstIndex(of: self)! }
    public var explanation: String {
        switch self {
        case .critical: return "Potential severe impact to a protected resource; review first."
        case .high: return "A significant boundary or exposure concern."
        case .medium: return "An observed change that needs investigation."
        case .low: return "Limited apparent impact in the available evidence; not a safety verdict."
        case .unassessed: return "Not enough information to assign a risk level."
        }
    }
    public static func suggested(for finding: Finding) -> Self {
        guard finding.confidence != .unknown else { return .unassessed }
        switch finding.severity { case .elevated: return .high; case .notice: return .medium; case .informational: return .low }
    }
}
public enum FindingReviewStatus: String, Codable, CaseIterable, Identifiable {
    case open, cleared, expected, falsePositive = "false-positive"
    public var id: String { rawValue }
    public var label: String { switch self { case .open: return "Open"; case .cleared: return "Cleared"; case .expected: return "Expected activity"; case .falsePositive: return "False positive" } }
}
/// Freeze the displayed queue and its review revisions before confirmation.
/// Findings arriving later must never be swept into a bulk clear.
public struct FindingReviewTarget: Codable {
    public var findingID: String
    public var expectedReviewID: String?
    public init(findingID: String, expectedReviewID: String?) {
        self.findingID = findingID; self.expectedReviewID = expectedReviewID
    }
}
public struct FindingReview: Codable, Identifiable, Equatable {
    public var id: String
    public var findingID: String
    public var timestamp: Date
    public var level: RiskLevel
    public var status: FindingReviewStatus
    public var previousLevel: RiskLevel
    public var previousStatus: FindingReviewStatus
    public var suggestedLevel: RiskLevel
    public var reason: String
}
public struct FindingAssessment: Codable, Identifiable {
    public var id: String { findingID }
    public var findingID: String
    public var suggestedLevel: RiskLevel
    public var level: RiskLevel
    public var status: FindingReviewStatus
    public var latestReview: FindingReview?
    public init(finding: Finding, reviews: [FindingReview] = []) {
        findingID = finding.id; suggestedLevel = RiskLevel.suggested(for: finding)
        latestReview = reviews.first { $0.findingID == finding.id }
        level = latestReview?.level ?? suggestedLevel; status = latestReview?.status ?? .open
    }
}
