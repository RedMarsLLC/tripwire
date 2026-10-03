import XCTest
import AppKit
import TripWireCore
@testable import TripWireApp

final class OverlayMetricsTests: XCTestCase {
    @MainActor func testLocalAppResourcesSurviveHidingAndClearOnShutdown() async throws {
        let date = Date()
        let app = AIApplication(id: "fixture", name: "Fixture", bundlePath: "/fixture", pid: 10)
        let model = OverlayMetricsModel(sample: { HostResourceCounters(timestamp: date, uptime: 100, cpu: nil, ram: nil) },
            applications: { [app] }, sampleApps: { apps in
                AppResourceSample(timestamp: date, uptime: 100, secondsPerTick: 1e-9, coreCount: 8, apps: apps,
                    processes: [AppProcessCounter(appID: app.id, pid: 10, started: 1, cpuTicks: 100, footprint: 4096)])
            })
        model.setVisible(true)
        defer { model.shutdown() }
        for _ in 0..<100 {
            if !model.appResources.readings.isEmpty { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTAssertEqual(model.appResources.totalMemory, 4096)
        XCTAssertNil(model.appResources.totalCPU)
        XCTAssertEqual(model.appResources.readings.first?.id, "fixture")
        XCTAssertEqual(DashboardRoute.appResources.screen, .agents)
        model.setVisible(false)
        XCTAssertTrue(model.isSampling)
        XCTAssertEqual(model.appResources.totalMemory, 4096)
        model.shutdown()
        XCTAssertTrue(model.appResources.readings.isEmpty)
        XCTAssertNil(model.appResources.lastSample)
    }
    @MainActor func testStoredAgentReportReachesOverlayAndItsDashboardEvidence() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        // Stable at the store's millisecond precision: rounding a submillisecond
        // receipt into the future must not make a frozen-clock fixture flaky.
        let url = directory.appendingPathComponent("events.sqlite"), now = Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down))
        let writer = try EventStore(url: url)
        let receipt = try AgentReceipt.parse(Data(#"{"session_id":"fixture-integration","hook_event_name":"PostToolUse","tool_name":"Bash","tool_use_id":"one"}"#.utf8), at: now)
        let other = try AgentReceipt.parse(Data(#"{"session_id":"other-fixture","hook_event_name":"Stop"}"#.utf8), provider: .claudeCode, at: now)
        try writer.recordAgentReceipt(receipt); try writer.recordAgentReceipt(other)
        let overlay = OverlayMetricsModel(sample: { HostResourceCounters(timestamp: now, uptime: 100, cpu: nil, ram: nil) }, now: { now })
        overlay.configure(storeURL: url)
        overlay.setVisible(true)
        defer { overlay.shutdown() }
        for _ in 0..<100 {
            if overlay.hooks.reports.count == 2 { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTAssertEqual(overlay.hooks.completions(at: now).count, 1)
        XCTAssertEqual(overlay.hookHistory.points(for: receipt.identity).last?.value, 1)
        XCTAssertEqual(overlay.hookHistory.points(for: other.identity).last?.value, 0)
        let dashboard = DashboardModel(storeURL: url)
        dashboard.route = .agents(receipt.identity)
        XCTAssertEqual(dashboard.route.screen, .agents)
        XCTAssertEqual(dashboard.agents.selecting(receipt.identity).reports.map(\.id), [receipt.id])
        XCTAssertEqual(try dashboard.event(id: receipt.id)?.sourceCollector, "codex-hooks")
        XCTAssertTrue(dashboard.view?.findings.isEmpty == true)
        overlay.configure(storeURL: directory.appendingPathComponent("different.sqlite"))
        XCTAssertTrue(overlay.hooks.reports.isEmpty)
        XCTAssertTrue(overlay.hookHistory.points(for: receipt.identity).isEmpty)
        XCTAssertEqual(DashboardRoute.page(.agents), .agents(nil))
    }
    @MainActor func testVisibilityDoesNotResetOrRestartSampling() async {
        var calls = 0
        let now = Date()
        let model = OverlayMetricsModel(sample: {
            calls += 1
            return HostResourceCounters(timestamp: now, uptime: 100, cpu: CPUTicks(user: 1, system: 1, idle: 8, nice: 0), ram: RAMUsage(totalBytes: 1000, freePages: 2, pageSize: 100))
        }, now: { now })
        XCTAssertEqual(calls, 0)
        model.setVisible(true)
        XCTAssertEqual(calls, 1)
        XCTAssertNotNil(model.resources.latestRAM)
        XCTAssertNil(model.resources.cpu.points.last?.value)
        XCTAssertFalse(model.hooks.connected)
        model.setVisible(true)
        XCTAssertEqual(calls, 1)
        model.setVisible(false)
        XCTAssertTrue(model.isSampling)
        XCTAssertNotNil(model.resources.latestRAM)
        XCTAssertTrue(model.resources.isFresh(at: now))
        model.setVisible(true)
        XCTAssertEqual(calls, 1, "Reopening must not reset counters or start another timer")
        model.shutdown()
        XCTAssertNil(model.resources.latestRAM)
        XCTAssertFalse(model.resources.isFresh(at: now))
        XCTAssertEqual(model.resources.pressure, .unknown)
        model.setVisible(true)
        XCTAssertEqual(calls, 2)
        model.shutdown()
    }
    @MainActor func testSleepCreatesRealGapAndWakeResumesWhileOverlayIsHidden() async {
        var calls = 0
        var now = Date()
        let model = OverlayMetricsModel(sample: {
            calls += 1
            return HostResourceCounters(timestamp: now, uptime: 100, cpu: nil, ram: nil)
        }, now: { now }, applications: { [] })
        model.setVisible(true)
        model.setVisible(false)
        now = now.addingTimeInterval(1)
        NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.willSleepNotification, object: nil)
        XCTAssertNil(model.resources.lastSample)
        XCTAssertFalse(model.isSampling)
        now = now.addingTimeInterval(10)
        NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.didWakeNotification, object: nil)
        XCTAssertEqual(calls, 2)
        XCTAssertNil(model.resources.cpu.points.last?.value)
        XCTAssertTrue(model.resources.cpu.points.contains { $0.reason?.contains("Sleep") == true })
        XCTAssertTrue(model.isSampling)
        XCTAssertFalse(model.isVisible)
        model.shutdown()
        now = now.addingTimeInterval(10)
        NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.didWakeNotification, object: nil)
        XCTAssertFalse(model.isSampling, "Wake must not restart a shut-down sampler")
    }
    @MainActor func testHiddenOverlayKeepsCPUAndSwapAppAndHookHistoryContinuous() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let base = Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down))
        let url = directory.appendingPathComponent("events.sqlite")
        let writer = try EventStore(url: url)
        let receipt = try AgentReceipt.parse(Data(#"{"session_id":"hidden-fixture","hook_event_name":"PostToolUse","tool_name":"Bash","tool_use_id":"one"}"#.utf8), at: base)
        try writer.recordAgentReceipt(receipt)
        let app = AIApplication(id: "fixture", name: "Fixture", bundlePath: "/fixture", pid: 10)
        let apps = AdvancingAppFixture(base: base)
        var calls = 0
        let model = OverlayMetricsModel(sample: {
            calls += 1
            return HostResourceCounters(timestamp: base.addingTimeInterval(Double(calls - 1)), uptime: Double(100 + calls),
                cpu: CPUTicks(user: UInt64(calls * 20), system: 0, idle: UInt64(calls * 80), nice: 0),
                ram: RAMUsage(totalBytes: 1000, freePages: 2, pageSize: 100),
                swap: SwapCounters(pageIns: UInt64(calls * 10), pageOuts: UInt64(calls), pageSize: 4096))
        }, now: { base.addingTimeInterval(Double(calls - 1)) }, applications: { [app] }, sampleApps: { apps.next($0) })
        model.configure(storeURL: url)
        model.setVisible(true)
        defer { model.shutdown() }
        for _ in 0..<200 {
            if model.appResources.totalCPU != nil && model.hookHistory.points(for: receipt.identity).count >= 2 { break }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        let hostBefore = try XCTUnwrap(model.resources.lastSample)
        let appBefore = try XCTUnwrap(model.appResources.lastSample)
        let hookBefore = try XCTUnwrap(model.hookHistory.points(for: receipt.identity).last?.timestamp)
        model.setVisible(false)
        try await Task.sleep(nanoseconds: 3_300_000_000)
        XCTAssertTrue(model.isSampling); XCTAssertFalse(model.isVisible)
        XCTAssertGreaterThan(try XCTUnwrap(model.resources.lastSample), hostBefore)
        XCTAssertGreaterThan(try XCTUnwrap(model.appResources.lastSample), appBefore)
        XCTAssertGreaterThan(try XCTUnwrap(model.hookHistory.points(for: receipt.identity).last?.timestamp), hookBefore)
        XCTAssertTrue(model.resources.cpu.points.dropFirst().allSatisfy { $0.value != nil })
        XCTAssertTrue(model.resources.swapIn.points.dropFirst().allSatisfy { $0.value != nil })
        XCTAssertTrue(model.resources.swapOut.points.dropFirst().allSatisfy { $0.value != nil })
        XCTAssertNotNil(model.appResources.totalCPU)
        let cpu = model.resources.cpu.points, swap = model.resources.swapIn.points, appSample = model.appResources.lastSample
        model.setVisible(true)
        XCTAssertEqual(model.resources.cpu.points, cpu)
        XCTAssertEqual(model.resources.swapIn.points, swap)
        XCTAssertEqual(model.appResources.lastSample, appSample)
    }

    @MainActor func testBackgroundRefreshAdoptsReaderForNewEvidenceLinks() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("events.sqlite")
        let model = DashboardModel(storeURL: url)
        let writer = try EventStore(url: url)
        let receipt = try CodexHookReceipt.parse(Data(#"{"session_id":"fixture","hook_event_name":"PostToolUse","tool_name":"Bash","tool_use_id":"one"}"#.utf8))
        try writer.recordCodexHook(receipt)
        model.refreshInBackground()
        for _ in 0..<100 {
            if model.view?.events.contains(where: { $0.id == receipt.id }) == true { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTAssertEqual(try model.event(id: receipt.id)?.id, receipt.id)
        XCTAssertTrue(model.store?.isReadOnly == true)
    }

}

/// Synthetic monotonic resource counters used only by the timer regression.
private final class AdvancingAppFixture {
    private let lock = NSLock()
    private let base: Date
    private var count = 0
    init(base: Date) { self.base = base }
    func next(_ apps: [AIApplication]) -> AppResourceSample {
        lock.lock(); defer { lock.unlock() }
        count += 1
        return AppResourceSample(timestamp: base.addingTimeInterval(Double(count - 1)), uptime: Double(100 + count),
            secondsPerTick: 0.001, coreCount: 4, apps: apps,
            processes: [AppProcessCounter(appID: "fixture", pid: 10, started: 1, cpuTicks: UInt64(count * 1000), footprint: 4096)])
    }
}
