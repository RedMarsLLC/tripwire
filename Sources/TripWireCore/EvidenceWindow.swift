import Foundation

public struct EvidenceWindow {
    public var events: [EvidenceEvent]
    public var findings: [Finding]
    public var eventsTruncated: Bool
    public var findingsTruncated: Bool
}
