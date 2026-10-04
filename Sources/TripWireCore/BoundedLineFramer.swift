import Foundation

/// Bounds a streaming line before decoding it. Empty output denotes a rejected
/// oversized line, so callers can record loss without retaining its contents.
public struct BoundedLineFramer {
    private let limit: Int
    private var buffer = Data()
    private var dropping = false
    public init(limit: Int = 262_144) { self.limit = max(1, limit) }
    public mutating func consume(_ chunk: Data, line: (Data) throws -> Void) rethrows {
        // Append chunks, not individual bytes: the latter saturates a CPU on a
        // busy system-wide JSONL feed even when almost no rows match a boundary.
        let pieces = chunk.split(separator: 10, omittingEmptySubsequences: false)
        for piece in pieces.dropLast() {
            append(piece)
            if dropping { try line(Data()) }
            else if !buffer.isEmpty { try line(buffer) }
            buffer.removeAll(keepingCapacity: true); dropping = false
        }
        if let last = pieces.last { append(last) }
    }
    public mutating func finish(line: (Data) throws -> Void) rethrows {
        if dropping { try line(Data()) }
        else if !buffer.isEmpty { try line(buffer) }
        buffer.removeAll(keepingCapacity: true); dropping = false
    }
    private mutating func append(_ bytes: Data.SubSequence) {
        guard !dropping else { return }
        if bytes.count > limit - buffer.count { buffer.removeAll(keepingCapacity: true); dropping = true }
        else { buffer.append(contentsOf: bytes) }
    }
}
