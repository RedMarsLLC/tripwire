import Foundation
#if os(Windows)
import ucrt
import CTripWirePlatform
#elseif canImport(Darwin)
import Darwin
#else
import Glibc
#endif
import TripWireCore
import TripWireCollectors
import TripWireTerminal

@main struct TripWireCLI {
    static func main() async {
        #if !os(Windows)
        umask(0o077)
        #endif
        do { try await run() }
        catch { FileHandle.standardError.write(Data("tripwire: \(TerminalText.safe(String(describing: error)))\n".utf8)); exit(1) }
    }
    static func run() async throws {
        // Hook adapter never decides permissions or modifies a tool call. Errors
        // are silent to the caller; the dashboard cannot infer delivery from silence.
        if CommandLine.arguments.dropFirst().first == "agent-hook" {
            do {
                var data = Data()
                while let chunk = try FileHandle.standardInput.read(upToCount: min(32768, 1_048_577 - data.count)), !chunk.isEmpty {
                    data.append(chunk)
                    if data.count > 1_048_576 { break }
                }
                let options = Array(CommandLine.arguments.dropFirst(2))
                var provider = AgentProvider.codex
                if !options.isEmpty {
                    guard options.count == 2, options[0] == "--provider", let selected = AgentProvider(rawValue: options[1]) else { throw TripWireError.message("Invalid adapter arguments") }
                    provider = selected
                }
                let receipt = try AgentReceipt.parse(data, provider: provider)
                try EventStore().recordAgentReceipt(receipt)
            } catch { /* No raw hook input or error payload is logged. */ }
            FileHandle.standardOutput.write(Data("{}\n".utf8))
            return
        }
        var args = Array(CommandLine.arguments.dropFirst())
        func flag(_ name: String) -> Bool { if let i = args.firstIndex(of: name) { args.remove(at: i); return true }; return false }
        let json = flag("--json"), ascii = flag("--ascii"), once = flag("--once"), controlStdin = flag("--control-stdin")
        var url = EventStore.defaultURL
        if let i = args.firstIndex(of: "--db") { guard i + 1 < args.count else { throw TripWireError.message("--db requires a file path") }; url = URL(fileURLWithPath: (args[i + 1] as NSString).expandingTildeInPath); args.removeSubrange(i...i + 1) }
        let command = args.first ?? (TerminalRuntime.isOutputTerminal ? "tui" : "status")
        if ["help", "--help", "-h"].contains(command) { safePrint(help); return }
        if command == "metrics" { try await ResourceStream.run(once: once); return }
        if command == "tripwires" { try TripwireCommands.run(Array(args.dropFirst()), url: url, json: json); return }
        guard ["investigate", "view", "files", "agents", "status", "sensors", "events", "findings", "network", "listeners", "processes", "applications", "persistence", "extensions", "hardware", "baseline", "explain", "doctor", "coverage", "health", "sample", "monitor", "tui", "canary"].contains(command) else { throw TripWireError.message("Unknown command. Use tripwire help") }
        if command == "baseline", args.count > 1, args[1] != "approve" { throw TripWireError.message("Baseline reset is not implemented. Only explicit fingerprint approval is supported.") }
        let changesStore = ["sample", "monitor", "canary"].contains(command) || (command == "baseline" && args.count > 1)
        let store = try EventStore(url: url, access: changesStore ? .readWrite : .readOnly)
        func emit<T: Encodable>(_ value: T) throws { Swift.print(String(decoding: try JSONEncoder.stable.encode(value), as: UTF8.self)) }
        switch command {
        case "view": try emit(DesktopSnapshot(store: store))
        case "investigate":
            guard args.count == 3, let start = ISO8601DateFormatter().date(from: args[1]), let end = ISO8601DateFormatter().date(from: args[2]), end > start, end.timeIntervalSince(start) <= 86400 else { throw TripWireError.message("Usage: tripwire investigate START-ISO8601 END-ISO8601 --json (up to 24 hours)") }
            try emit(store.readSnapshot { try store.evidence(in: DateInterval(start: start, end: end)) })
        case "agents":
            let now = Date(), activity = try store.agentActivity()
            if json { try emit(activity.identities) } else {
                safePrint("AGENT REPORTS / application-reported metadata / coverage UNKNOWN")
                safePrint("Adapters: Codex, Claude Code, Cursor; generic v1 contract. Installation and live delivery are separate.")
                if !activity.hasReports { safePrint("NO REPORTS RECEIVED / no live integration established") }
                if activity.truncated { safePrint("LIMITED: report window truncated") }
                for receipt in activity.identities {
                    let selected = activity.selecting(receipt.identity)
                    safePrint("\(receipt.label): \(selected.completions(at: now).count) completion reports / last 60s; \(selected.lifecycle(at: now)); last \(TimeText.iso(receipt.timestamp))")
                }
                safePrint("Silence does not establish idle; unknown/unconfigured agents are not enumerated. Reports are not kernel attestation.")
            }
        case "sample":
            let monitor = Monitor(store: store)
            do { try await monitor.sample(); try monitor.stop() } catch { try? monitor.stop(); throw error }
            safePrint("Snapshot stored. Collector owner STOPPED; this was not continuous monitoring.\n\(url.path)")
        case "monitor":
            let interval = args.count > 1 ? Double(args[1]) ?? 15 : 15
            guard interval >= 5 && interval <= 3600 else { throw TripWireError.message("Polling interval must be 5...3600 seconds") }
            let monitor = Monitor(store: store)
            let stop = StopToken()
            if controlStdin {
                // Private parent/child control channel; never monitored process input.
                DispatchQueue.global().async {
                    var command = Data()
                    do {
                        while command.count < 5 {
                            guard let part = try FileHandle.standardInput.read(upToCount: 5 - command.count), !part.isEmpty else { stop.request(); return }
                            command.append(part)
                        }
                        if command == Data("stop\n".utf8) { stop.request() }
                    } catch { stop.request() }
                }
            }
            #if os(Windows)
            let consoleHandler = tw_interrupt_begin() == 0
            guard consoleHandler || controlStdin else { throw TripWireError.message("Cannot register console stop handler") }
            defer { if consoleHandler { tw_interrupt_end() }; try? monitor.stop() }
            #else
            signal(SIGINT, SIG_IGN); signal(SIGTERM, SIG_IGN)
            let intSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .global()), termSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())
            for source in [intSource, termSource] { source.setEventHandler { stop.request() }; source.resume() }
            defer { intSource.cancel(); termSource.cancel(); try? monitor.stop() }
            #endif
            safePrint("TRIPWIRE foreground monitoring. Interval \(interval)s. No background installation. Ctrl-C stops.")
            repeat {
                try await monitor.sample(continuousFiles: !once)
                safePrint("\(TimeText.iso(Date())) sample stored; source limitations remain. Use tripwire tui in another terminal.")
                if once { break }
                let until = Date().addingTimeInterval(interval)
                while !stop.stopped && Date() < until { try await Task.sleep(nanoseconds: 200_000_000) }
            } while !stop.stopped
        case "tui":
            if once { safePrint(ConsoleRenderer.render(try StoreView(store: store), ascii: ascii || !TerminalRuntime.isOutputTerminal)) }
            // macOS terminals support the original Unicode artwork even when
            // LANG is unset. Use --ascii for an explicit basic-character fallback.
            else { try InteractiveConsole(store: store).run(ascii: ascii) }
        case "status":
            let view = try StoreView(store: store)
            if json { try emit(["coverage": view.coverage, "lastSample": view.sampledAt, "openFindings": String(view.findings.count), "database": view.databaseHealth]) }
            else { safePrint("TRIPWIRE / HOST SECURITY WATCHDOG\nCoverage: \(view.coverage)\nLast snapshot: \(view.sampledAt)\nOpen findings: \(view.findings.count)\nChanges in last 200 events: \(view.changes)\nUnknown observations: \(view.unknowns)\nEvent store quick_check: \(view.databaseHealth)\nNo findings does not establish safety. Run doctor for limitations.") }
        case "sensors":
            let sensors = try store.sensors().map { $0.effective() }
            if json { try emit(sensors) } else {
                if sensors.isEmpty { safePrint("UNKNOWN: no sensor has reported. Run sample or foreground monitor.") }
                for s in sensors { safePrint("\(s.descriptor.name): \(s.state.rawValue) / \(s.visibility.rawValue)\n  Source: \(s.descriptor.source)\n  Monitors: \(s.descriptor.monitors)\n  Permissions: \(s.descriptor.permissions.joined(separator: "; "))\n  Detail: \(s.detail)\n  Last event: \(TimeText.iso(s.lastEvent)) / heartbeat: \(TimeText.iso(s.lastHeartbeat)) / success: \(TimeText.iso(s.lastSuccess))\n  Limitations: \(s.descriptor.limitations.joined(separator: "; "))") }
            }
        case "events":
            let events = try store.events()
            if json { try emit(events) } else { for e in events { safePrint(TerminalText.safe("\(ConsoleRenderer.eventLine(e)) ID \(e.id)")) } }
        case "findings":
            let findings = try store.findings()
            if json { try emit(findings) } else {
                if findings.isEmpty { safePrint("NO OPEN FINDINGS / visibility limitations remain") }
                for f in findings { safePrint(TerminalText.safe("\(f.id) \(f.title) / observation confidence \(f.confidence.rawValue) / intent UNKNOWN")) }
            }
        case "explain":
            guard args.count > 1 else { throw TripWireError.message("Usage: tripwire explain FINDING-ID") }
            let matches = try store.findings().filter { $0.id.hasPrefix(args[1]) }
            guard matches.count == 1, let f = matches.first else { throw TripWireError.message("Finding ID absent or ambiguous") }
            if json { try emit(f) } else { for line in Explain.text(f, events: try f.eventIDs.compactMap { try store.event(id: $0) }).components(separatedBy: "\n") { safePrint(TerminalText.safe(line)) } }
        case "coverage", "doctor", "health":
            let view = try StoreView(store: store)
            if json { try emit(DoctorReport(view: view)) } else {
                safePrint("TRIPWIRE DOCTOR\nDatabase quick_check: \(view.databaseHealth)\nLast completed sample: \(view.sampledAt)\nCoverage: \(view.coverage)\nNo privileges or permissions are requested by doctor.")
                for s in view.sensors { safePrint(TerminalText.safe("\(s.descriptor.name): \(s.state.rawValue) / \(s.visibility.rawValue)\n\(s.detail)")); safePrint("  Required: \(s.descriptor.permissions.isEmpty ? "No additional grant for declared scope" : s.descriptor.permissions.joined(separator: "; "))\n  Last heartbeat: \(TimeText.iso(s.lastHeartbeat)); success: \(TimeText.iso(s.lastSuccess))\n  Drops: \(s.droppedEvents.map(String.init) ?? "UNKNOWN"); backlog: \(s.queueBacklog.map(String.init) ?? "UNKNOWN")") }
                if view.sensors.isEmpty { for c in CollectorRegistry.make(storeURL: url) { safePrint("\(c.descriptor.name): UNKNOWN / NOT STARTED") } }
                safePrint("COVERAGE TIMELINE (\(view.gaps.count) stored intervals)")
                for gap in view.gaps.prefix(30) { safePrint("\(TimeText.iso(gap.start)) -> \(TimeText.iso(gap.end)) \(gap.collector): \(gap.reason)") }
                safePrint("Platform: \(HostPlatform.current.displayName). Permission denial and unimplemented adapters are distinct. No percentage is computed. Unknown event loss is not zero event loss.")
            }
        case "baseline" where args.count > 1 && args[1] == "approve":
            guard args.count == 6, args[3] == "--fingerprint", args[5] == "--confirm" else { throw TripWireError.message("Usage: tripwire baseline approve EXACT-INVENTORY-ID --fingerprint SHA256 --confirm (approves only current fingerprint)") }
            try store.approve(key: args[2], expectedFingerprint: args[4]); safePrint("Current fingerprint USER APPROVED. Original baseline and evidence retained; approval is not a safety verdict.")
        case "canary":
            guard args.count == 3, args[1] == "create", !args[2].isEmpty, args[2].count <= 60, args[2].allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }) else { throw TripWireError.message("Usage: tripwire canary create NAME (letters, digits, hyphen, underscore)") }
            #if !os(macOS)
            throw TripWireError.message("Canary creation is unavailable in this platform adapter")
            #else
            let directory = url.deletingLastPathComponent().appendingPathComponent("Canaries")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try SafeFile.requirePrivateDirectory(directory)
            let marker = directory.appendingPathComponent(args[2] + ".marker")
            let directoryFD = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard directoryFD >= 0 else { throw TripWireError.message("Cannot open canary directory") }
            defer { close(directoryFD) }
            let fd = openat(directoryFD, args[2] + ".marker", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw TripWireError.message("Marker already exists or cannot be created") }
            let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
            try handle.write(contentsOf: Data("TripWire harmless local canary marker\n".utf8)); try handle.close()
            safePrint("Created \(marker.path). Run sample to establish its baseline. Reads/accesses are NOT OBSERVABLE.")
            #endif
        default:
            let map: [String: [EventClass]] = ["files": [.file], "network": [.network, .listener], "listeners": [.listener], "processes": [.process], "applications": [.application], "persistence": [.persistence], "extensions": [.extensions], "hardware": [.hardware]]
            let records = try store.inventory().filter { map[command] == nil || map[command]!.contains($0.observation.eventClass) }
            if json { try emit(records) } else {
                if command == "files" {
                    safePrint("AI OPEN-FILE SNAPSHOTS / last observed, not a read/write event audit")
                    for limitation in AIFileAccessCollector().descriptor.limitations { safePrint(limitation) }
                    if let health = try store.sensors().first(where: { $0.id == AIFileAccessCollector.id })?.effective() {
                        safePrint("Source: \(health.state.rawValue) / \(health.visibility.rawValue) / \(health.detail)")
                    }
                }
                for r in records { safePrint(TerminalText.safe("\(r.baselineStatus.rawValue) \(r.observation.component)\nID \(r.id)")); safePrint("  Fingerprint \(r.observation.fingerprint)"); safePrint("  First \(TimeText.iso(r.firstSeen)) / Last \(TimeText.iso(r.lastSeen)) / observations \(r.observationCount) / \(r.present ? "last observed present" : "observed absent")")
                    for key in r.observation.attributes.keys.sorted() { safePrint(TerminalText.safe("  \(key): \(r.observation.attributes[key]!)")) }
                }
                if records.isEmpty { safePrint("No stored records in this scope. Visibility UNKNOWN until the sensor reports.") }
            }
        }
    }
    static let help = """
    TRIPWIRE / host security watchdog
    tripwire [COMMAND] [--db PATH] [--json] [--ascii]
    tui                 Interactive store view; default when stdout is a terminal
    sample              One bounded read-only collection, then STOPPED
    monitor [SECONDS]   Foreground inventories (default 15s); file snapshots ~2s; Ctrl-C stops
    view                Bounded read-only JSON snapshot for the desktop UI
    metrics             JSON-lines host metrics every second; --once takes two counter samples
    status sensors events findings network listeners processes persistence
    applications extensions hardware baseline coverage health doctor agents files
    agent-hook [--provider codex|claude-code|cursor|generic]  Opt-in metadata stdin adapter
    tripwires [list|save|enable|disable|delete]  Configure AI-associated boundary alerts
    tripwires save --name NAME --path ABSOLUTE-PATH --kind file|folder|application
    explain FINDING-ID  Full evidence, limitations and investigation guidance
    baseline approve EXACT-INVENTORY-ID --fingerprint SHA256 --confirm
    canary create NAME  Opt-in harmless marker in the event-store directory
    --once              Single frame/sample for tui or monitor
    view --json: bounded desktop snapshot. metrics [--once]: host CPU/RAM JSON stream.
    investigate START-ISO8601 END-ISO8601 --json: bounded evidence for a time range.
    All interfaces share one SQLite store. No daemon, extension or login item is installed.
    """
}
// State is protected by the lock; the Windows interrupt flag is atomic in the C adapter.
private final class StopToken: @unchecked Sendable {
    private let lock = NSLock(); private var value = false
    var stopped: Bool {
        #if os(Windows)
        if tw_interrupted() != 0 { return true }
        #endif
        lock.lock(); defer { lock.unlock() }; return value
    }
    func request() { lock.lock(); value = true; lock.unlock() }
}
private struct DoctorReport: Encodable {
    var database: String; var sampledAt: String; var sensors: [SensorHealth]; var gaps: [CoverageGap]
    init(view: StoreView) { database = view.databaseHealth; sampledAt = view.sampledAt; sensors = view.sensors; gaps = view.gaps }
}

// Every human-readable CLI sink treats metadata as text, including sensor failure paths.
private func safePrint(_ value: String) {
    let lines = value.components(separatedBy: "\n").map(TerminalText.safe)
    Swift.print(lines.joined(separator: "\n"))
}
