import XCTest
import Foundation
@testable import TripWireCore

final class TripwireRuleTests: XCTestCase {
    func store() throws -> (EventStore, URL) {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("tripwire-rule-tests-\(UUID().uuidString)")
        return (try EventStore(url: directory.appendingPathComponent("events.sqlite")), directory)
    }
    var target: String { HostPlatform.current == .windows ? "C:/private/keys" : "/private/keys" }
    func fileSample(path: String? = nil, pid: Int32 = 21, launch: TimeInterval = 10, partial: Bool = false) -> CollectorSnapshot {
        let path = path ?? target + "/key"
        let process = ProcessIdentity(pid: pid, uid: 1000, executablePath: "/fixture/ai-helper", launchTime: Date(timeIntervalSince1970: launch))
        let row = Observation(key: "\(pid):\(launch):\(path)", eventClass: .file, component: path,
            attributes: ["path": path, "associatedApp": "TEST AI", "associationBasis": "Synthetic test association", "openMode": "READ CAPABLE"], process: process, confidence: .moderate)
        return CollectorSnapshot(descriptor: SensorDescriptor("ai-open-files", "Test", source: "TEST ONLY", monitors: "Fixture handles"), observations: [row], complete: !partial, absenceReliable: false, state: partial ? .error : .degraded, visibility: .limited, detail: partial ? "Fixture partial source" : "Fixture")
    }
    func testPathBoundariesAndNormalization() throws {
        let folder = TripwireRule(name: "Keys", path: "/private/keys", kind: .folder, platform: .linux)
        XCTAssertTrue(TripwirePath.matches("/private/keys/one", rule: folder))
        XCTAssertFalse(TripwirePath.matches("/private/keys-copy/one", rule: folder))
        XCTAssertFalse(TripwirePath.matches("/private/keys/../public/one", rule: folder))
        let windows = TripwireRule(name: "Keys", path: #"C:\Users\Test\.SSH"#, kind: .folder, platform: .windows)
        XCTAssertTrue(TripwirePath.matches("/C:/users/test/.ssh/key", rule: windows))
        XCTAssertFalse(TripwirePath.matches("C:/users/test/.ssh-copy/key", rule: windows))
        XCTAssertThrowsError(try TripwireRule(name: "Invalid", path: "relative/path", kind: .file).validated())
        XCTAssertThrowsError(try TripwireRule(name: "Invalid", path: "/file\nforged", kind: .file).validated())
    }
    func testRulesPersistWithoutOpeningTargetsAndReaderCannotWrite() throws {
        let (writer, directory) = try store(); defer { try? FileManager.default.removeItem(at: directory) }
        let target = directory.appendingPathComponent("nonexistent/secret").path
        let rule = TripwireRule(name: "Private boundary", path: target, kind: .folder)
        try writer.saveTripwire(rule)
        let reader = try EventStore(url: writer.url, access: .readOnly)
        XCTAssertEqual(try reader.tripwireRules().first?.name, rule.name)
        XCTAssertFalse(FileManager.default.fileExists(atPath: target))
        XCTAssertThrowsError(try reader.saveTripwire(rule))
        XCTAssertThrowsError(try reader.deleteTripwire(id: rule.id))
        XCTAssertTrue(try writer.findings().isEmpty)
        try writer.deleteTripwire(id: rule.id)
        XCTAssertTrue(try writer.tripwireRules().isEmpty)
        XCTAssertEqual(try writer.events().filter { $0.sourceCollector == "tripwire-configuration" }.count, 2)
    }
    func testRuleAddedAfterBaselineMatchesNextSnapshotAndDeduplicatesAcrossReaders() throws {
        let (writer, directory) = try store(); defer { try? FileManager.default.removeItem(at: directory) }
        let sample = fileSample(); try writer.ingest(sample)
        let rule = TripwireRule(name: "Keys", path: target, kind: .folder)
        try writer.saveTripwire(rule)
        XCTAssertTrue(try writer.findings().isEmpty, "Old inventory is not a fresh access")
        try writer.ingest(sample); try writer.ingest(sample)
        let reopened = try EventStore(url: writer.url)
        try reopened.ingest(sample)
        let hits = try reopened.findings().filter { $0.ruleID == "user-tripwire:" + rule.id }
        XCTAssertEqual(hits.count, 1)
        let finding = try XCTUnwrap(hits.first)
        XCTAssertNotNil(try reopened.event(id: XCTUnwrap(finding.eventIDs.first)))
        XCTAssertTrue(finding.whyFlagged.contains("Keys")); XCTAssertEqual(finding.intent, "UNKNOWN")
        try reopened.ingest(fileSample(launch: 20))
        XCTAssertEqual(try reopened.findings().count, 2, "PID reuse with a different start time is a new instance")
    }
    func testDisableAndPartialSourceRemainHonest() throws {
        let (writer, directory) = try store(); defer { try? FileManager.default.removeItem(at: directory) }
        var rule = TripwireRule(name: "Keys", path: target, kind: .folder, enabled: false)
        try writer.saveTripwire(rule); try writer.ingest(fileSample()); XCTAssertTrue(try writer.findings().isEmpty)
        rule.enabled = true; try writer.saveTripwire(rule); try writer.ingest(fileSample(partial: true))
        let hit = try XCTUnwrap(writer.findings().first)
        XCTAssertTrue(hit.limitations.contains { $0.contains("Partial source") })
        try writer.deleteTripwire(id: rule.id); try writer.ingest(fileSample(pid: 99))
        XCTAssertEqual(try writer.findings().count, 1, "Deleting a rule preserves alerts and stops future matches")
    }
    func testApplicationRequiresAIAncestryAndRejectsReusedParentPID() {
        let start = Date(timeIntervalSince1970: 100)
        let parent = ProcessIdentity(pid: 10, uid: 1000, executablePath: "/opt/codex", launchTime: start)
        let child = ProcessIdentity(pid: 20, parentPID: 10, uid: 1000, executablePath: "/opt/forbidden", launchTime: start.addingTimeInterval(1))
        XCTAssertNotNil(TripwireMatcher.aiAncestor(child, processes: [10: parent, 20: child], platform: .linux))
        XCTAssertNil(TripwireMatcher.aiAncestor(child, processes: [20: child], platform: .linux))
        var reused = parent; reused.launchTime = start.addingTimeInterval(2)
        XCTAssertNil(TripwireMatcher.aiAncestor(child, processes: [10: reused], platform: .linux))
        var foreign = parent; foreign.uid = 2000
        XCTAssertNil(TripwireMatcher.aiAncestor(child, processes: [10: foreign], platform: .linux))
        var unknown = parent; unknown.launchTime = nil
        XCTAssertNil(TripwireMatcher.aiAncestor(child, processes: [10: unknown], platform: .linux))
    }
    func testApplicationMatchesProcessEvidenceButFileRuleDoesNotInventFileAccess() {
        let parent = ProcessIdentity(pid: 10, uid: 1000, executablePath: "/opt/codex", launchTime: Date(timeIntervalSince1970: 10))
        let child = ProcessIdentity(pid: 20, parentPID: 10, uid: 1000, executablePath: "/opt/private-app", launchTime: Date(timeIntervalSince1970: 20))
        let rows = [parent, child].map { Observation(key: $0.instanceKey!, eventClass: .process, component: $0.executablePath!, attributes: ["executable": $0.executablePath!], process: $0) }
        var snapshot = CollectorSnapshot(descriptor: SensorDescriptor("processes", "Test processes", source: "TEST ONLY", monitors: "Fixture process tree"), observations: rows, complete: false, state: .degraded, visibility: .limited, detail: "Fixture")
        let application = TripwireRule(name: "Private app", path: "/opt/private-app", kind: .application, platform: .linux)
        let file = TripwireRule(name: "No inferred reads", path: "/opt/private-app", kind: .file, platform: .linux)
        XCTAssertEqual(TripwireMatcher.matches(snapshot, rules: [application, file], platform: .linux).map { $0.rule.id }, [application.id])
        snapshot.observations = [rows[1]]
        XCTAssertTrue(TripwireMatcher.matches(snapshot, rules: [application], platform: .linux).isEmpty)
        snapshot.observations = rows; snapshot.visibility = .unavailable
        XCTAssertTrue(TripwireMatcher.matches(snapshot, rules: [application], platform: .linux).isEmpty)
    }
    func testExactFilesAndAppBundlesDoNotMatchPrefixLookalikes() {
        let file = TripwireRule(name: "Key", path: "/private/key", kind: .file, platform: .macOS)
        XCTAssertTrue(TripwirePath.matches("/private/key", rule: file))
        XCTAssertFalse(TripwirePath.matches("/private/key/child", rule: file))
        let app = TripwireRule(name: "App", path: "/Applications/Private.app", kind: .application, platform: .macOS)
        XCTAssertTrue(TripwirePath.matches("/Applications/Private.app/Contents/MacOS/Private", rule: app))
        XCTAssertFalse(TripwirePath.matches("/Applications/Private.app.backup/Contents/MacOS/Private", rule: app))
    }
}
