import Foundation
import TripWireCore
import TripWireTerminal

enum ReviewCommand {
    static let usage = "tripwire review FINDING-ID [--level critical|high|medium|low|unassessed --status open|cleared|expected|false-positive --reason TEXT --expected-review UUID|none] [--json]; or tripwire review --clear-queue [--json] with a JSON array of findingID/expectedReviewID objects on stdin"
    struct ReviewView: Encodable { var assessment: FindingAssessment; var history: [FindingReview]; var accessContext: [String] }
    static func run(_ args: [String], url: URL, json: Bool) throws {
        if args == ["--clear-queue"] {
            var data = Data()
            while let chunk = try FileHandle.standardInput.read(upToCount: min(32768, 1_048_577 - data.count)), !chunk.isEmpty {
                data.append(chunk)
                guard data.count <= 1_048_576 else { throw TripWireError.message("Queue selection exceeds 1 MiB.") }
            }
            let targets = try JSONDecoder().decode([FindingReviewTarget].self, from: data)
            let count = try EventStore(url: url).clearFindingQueue(targets)
            if json { print("{\"cleared\":\(count)}") }
            else { print("\(count) findings moved to Reviewed with status Cleared. Evidence retained; future alerts remain enabled.") }
            return
        }
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
        if json { print(String(decoding: try JSONEncoder.stable.encode(ReviewView(assessment: assessment, history: history, accessContext: try finding.eventIDs.compactMap { try reader.event(id: $0) }.compactMap(AccessContext.text))), as: UTF8.self)) }
        else {
            print(TerminalText.safe("\(assessment.level.label) · \(assessment.status.label) · original suggestion: \(assessment.suggestedLevel.label)"))
            for review in history { print(TerminalText.safe("\(TimeText.iso(review.timestamp)) · \(review.level.label) / \(review.status.label): \(review.reason)")) }
            print("Corrections apply only to this finding. Evidence is unchanged; future alerts remain enabled.")
        }
    }
}
