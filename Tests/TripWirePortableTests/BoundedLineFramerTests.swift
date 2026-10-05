import XCTest
import Foundation
import TripWireCore

final class BoundedLineFramerTests: XCTestCase {
    func testFragmentedLinesOversizeRecoveryAndEOF() {
        var framer = BoundedLineFramer(limit: 4), rows: [Data] = []
        for chunk in ["ab", "cd\n\n12", "345678", "9\nx\ny"] {
            framer.consume(Data(chunk.utf8)) { rows.append($0) }
        }
        framer.finish { rows.append($0) }
        XCTAssertEqual(rows.map { String(decoding: $0, as: UTF8.self) }, ["abcd", "", "x", "y"])
        framer.finish { _ in XCTFail("EOF must not repeat a line") }
    }
    func testOversizedEOFAndMultibyteBoundUseBytes() {
        var framer = BoundedLineFramer(limit: 3), rows: [Data] = []
        framer.consume(Data("😀".utf8)) { rows.append($0) }
        framer.finish { rows.append($0) }
        XCTAssertEqual(rows, [Data()])
    }
    func testBusyStreamDoesNotLoseOrMergeLinesAtReadBoundaries() {
        let line = Data((String(repeating: "metadata", count: 500) + "\n").utf8)
        var bytes = Data(); for _ in 0..<2000 { bytes.append(line) }
        var framer = BoundedLineFramer(), count = 0
        for start in stride(from: 0, to: bytes.count, by: 32768) {
            framer.consume(bytes[start..<min(bytes.count, start + 32768)]) { row in
                XCTAssertEqual(row, line.dropLast()); count += 1
            }
        }
        framer.finish { _ in XCTFail("All lines ended with a newline") }
        XCTAssertEqual(count, 2000)
    }
}
