import Foundation
import TripWireCore
import TripWireTerminal

enum ReviewCommand {
    static let usage = "tripwire review FINDING-ID [--level critical|high|medium|low|unassessed --status open|expected|false-positive --reason TEXT --expected-review UUID|none] [--json]"
    struct ReviewView: Encodable { var assessment: FindingAssessment; var history: [FindingReview] }
    static func run(_ args: [String], url: URL, json: Bool) throws {
        guard let id = args.first else { throw TripWireError.message(usage) }
        let reader = try EventStore(url: url, access: .readOnly)
        guard let finding = try reader.findings().first(where: { $0.id == id }) else { throw TripWireError.message("Exact finding ID not found") }
        if args.count > 1 {
            var options = Array(args.dropFirst())
            func take(_ key: String) throws -> String {
                guard let i = options.firstIndex(of: key), i + 1 < options.count else { throw TripWireError.message(usage) }
                let result = options[i + 1]; options.removeSubrange(i...i + 1); return result
            }
            let levelText = try take("--level"), statusText = try take("--status"), reason = try take("--reason"), revision = try take("--expected-review")
            guard options.isEmpty, let level = RiskLevel(rawValue: levelText), let status = FindingReviewStatus(rawValue: statusText), revision == "none" || UUID(uuidString: revision) != nil else { throw TripWireError.message(usage) }
            try EventStore(url: url).reviewFinding(id: id, level: level, status: status, reason: reason, expectedReviewID: revision == "none" ? nil : revision)
        }
        let history = try reader.findingReviews().filter { $0.findingID == id }
        let assessment = FindingAssessment(finding: finding, reviews: history)
        if json { print(String(decoding: try JSONEncoder.stable.encode(ReviewView(assessment: assessment, history: history)), as: UTF8.self)) }
        else {
            print(TerminalText.safe("\(assessment.level.label) · \(assessment.status.label) · original suggestion: \(assessment.suggestedLevel.label)"))
            for review in history { print(TerminalText.safe("\(TimeText.iso(review.timestamp)) · \(review.level.label) / \(review.status.label): \(review.reason)")) }
            print("Corrections apply only to this finding. Evidence is unchanged; future alerts remain enabled.")
        }
    }
}
