import Foundation

public struct EvidenceWindow: Encodable {
    public var events: [EvidenceEvent]
    public var findings: [Finding]
    public var eventsTruncated: Bool
    public var findingsTruncated: Bool
}
