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

public enum TerminalText {
    /// Treat collected names as data, never terminal controls (including OSC hyperlinks and bidi controls).
    public static func safe(_ value: String) -> String {
        String(String.UnicodeScalarView(value.unicodeScalars.map { scalar in
            if scalar.value < 32 || (127...159).contains(scalar.value) || (0x202A...0x202E).contains(scalar.value) || (0x2066...0x2069).contains(scalar.value) { return UnicodeScalar(32)! }
            return scalar
        }))
    }
    public static func fit(_ value: String, width: Int, ascii: Bool = false) -> String {
        let cleaned = safe(value)
        // Non-ASCII dynamic names use '?' in terminal table cells: predictable cell widths, no escape/combining-width injection.
        let stable = String(cleaned.unicodeScalars.map { $0.isASCII ? Character($0) : "?" })
        let cut = String(stable.prefix(max(0, width)))
        return cut + String(repeating: " ", count: max(0, width - cut.count))
    }
    public static let wordmark = #"""
       ████████╗██████╗ ██╗██████╗ ██╗    ██╗██╗██████╗ ███████╗
       ╚══██╔══╝██╔══██╗██║██╔══██╗██║    ██║██║██╔══██╗██╔════╝
          ██║   ██████╔╝██║██████╔╝██║ █╗ ██║██║██████╔╝█████╗
          ██║   ██╔══██╗██║██╔═══╝ ██║███╗██║██║██╔══██╗██╔══╝
          ██║   ██║  ██║██║██║     ╚███╔███╔╝██║██║  ██║███████╗
          ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝      ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝
              =====================================================*
                                                         .       .  \|/  .
                                                           ` -- (*) -- '
                                                                /|\
                                                               ' * '
    """#
    public static let asciiWordmark = #"""
       TTTTT RRRR  III PPPP  W   W III RRRR  EEEEE
         T   R   R  I  P   P W   W  I  R   R E
         T   RRRR   I  PPPP  W W W  I  RRRR  EEEE
         T   R  R   I  P     WW WW  I  R  R  E
         T   R   R III P     W   W III R   R EEEEE
          =====================================================*
                                                     .       .  \|/  .
                                                       ` -- (*) -- '
                                                            /|\
                                                           ' * '
    """#
}
public enum ConsoleRenderer {
    public static func render(_ view: StoreView, width: Int = 80, height: Int = 50, ascii: Bool = false, page: String = "overview", selection: Int = 0) -> String {
        if width < 28 || height < 12 {
            return ["TRIPWIRE", view.coverage, "Findings \(view.findings.count)", "[q] quit"].prefix(max(1, height)).map { String(TerminalText.fit($0, width: max(1, width), ascii: true).prefix(max(1, width))) }.joined(separator: "\n")
        }
        let w = max(1, width - 4), full = width >= 80 && height >= 44 && page == "overview"
        // The supplied wordmark and fuse fit a standard 80x24 terminal. Compact
        // the overview's data, rather than dropping its artwork at that size.
        let showArtwork = width >= 80 && height >= 24 && page == "overview"
        let artwork = (ascii ? TerminalText.asciiWordmark : TerminalText.wordmark).components(separatedBy: "\n")
        var lines: [String] = []
        if showArtwork {
            lines += artwork
            lines.append("HOST SECURITY WATCHDOG / Observe > Detect > Correlate")
        }
        else { lines.append("TRIPWIRE / HOST SECURITY WATCHDOG") }
        let compactArtwork = showArtwork && !full
        if compactArtwork {
            let sensors = view.sensors.isEmpty ? "UNKNOWN / no reports" : "\(view.sensors.filter { [.active, .degraded].contains($0.effective().state) }.count) CHECKS REPORTING; [c] scopes and next steps"
            lines += [
                "MODE STORE VIEW / collection requires sample or monitor",
                "COVERAGE \(view.coverage)",
                "LAST SAMPLE \(view.sampledAt)",
                "SENSORS \(sensors) / OPEN FINDINGS \(view.findings.count)",
                "Changes \(view.changes) (last 200 events) / Unknown observations \(view.unknowns) / Gaps \(view.gaps.count)",
                "No findings does not establish safety. [c] limits; event loss UNKNOWN"
            ]
        } else {
            lines += ["Observe > Baseline > Detect Change > Correlate > Explain > Preserve Evidence", "HOST \(ProcessInfo.processInfo.hostName)  \(HostPlatform.current.displayName) \(ProcessInfo.processInfo.operatingSystemVersionString)", "MODE STORE VIEW / collection requires sample or monitor", "COVERAGE \(view.coverage)  LAST SAMPLE \(view.sampledAt)", String(repeating: "-", count: w)]
        }
        switch page {
        case "overview" where compactArtwork:
            // Leave the full banner, current summary, limitations and navigation
            // visible together. Detailed evidence remains on the other pages.
            break
        case "overview":
            lines += ["SENSOR STATUS", "\(view.sensors.filter { [.active, .degraded].contains($0.effective().state) }.count) CHECKS REPORTING; scopes differ, not a coverage percentage"]
            lines += view.sensors.prefix(full ? 16 : 5).map { "\(TerminalText.fit($0.descriptor.name, width: min(37, max(10, w - 24)))) \($0.state.rawValue) / \($0.visibility.rawValue)" }
            if view.sensors.isEmpty { lines.append("UNKNOWN / No collectors have reported") }
            lines += [String(repeating: "-", count: w), "Trips \(view.findings.count)   Open findings \(view.findings.count)   Changes \(view.changes) (last 200 events)", "Unknown observations \(view.unknowns)   Stored gaps \(view.gaps.count)", "LIVE TRIPWIRE (stored observations; absence is not safety)"]
            lines += view.events.prefix(full ? 6 : 3).map(eventLine)
            if let finding = view.findings.first { lines += ["TRIPPED: \(finding.title)", "Observation confidence: \(finding.confidence.rawValue) / Intent: UNKNOWN", "Evidence records: \(finding.eventIDs.count) / [x] explanation"] }
            else { lines.append("NO OPEN FINDINGS / monitoring limitations still apply") }
            lines += ["Event store: \(view.databaseHealth)  ES event loss: UNKNOWN (no client)"]
        case "findings", "explain":
            lines.append("FINDINGS / j,k select / x explain / o overview")
            for (i, f) in view.findings.enumerated() { lines.append("\(i == selection ? ">" : " ") \(i + 1). \(f.title) [\(f.confidence.rawValue)] \(f.id)") }
            if view.findings.isEmpty { lines.append("NO OPEN FINDINGS") }
        case "events": lines += ["LIVE TRIPWIRE / most recent stored observations"] + view.events.map(eventLine)
        case "coverage", "doctor":
            lines += ["\(page.uppercased()) / explicit sensor scopes", "Database quick_check: \(view.databaseHealth)", "ES availability: UNAVAILABLE / entitlement-dependent adapter not installed", "Network Extension: UNAVAILABLE / provider not installed", "Dropped events: UNKNOWN for unavailable event streams", "Queue backlog: UNKNOWN for unavailable event streams"]
            for s in view.sensors { lines += ["\(s.descriptor.name): \(s.state.rawValue) / \(s.visibility.rawValue)", "  Heartbeat \(TimeText.iso(s.lastHeartbeat)) / success \(TimeText.iso(s.lastSuccess))", "  \(s.detail)"] }
            lines += ["COVERAGE TIMELINE"] + view.gaps.prefix(20).map { "\(TimeText.iso($0.start)) - \(TimeText.iso($0.end)) \($0.collector): \($0.reason)" }
        default:
            let classes: [EventClass] = page == "network" ? [.network, .listener] : page == "processes" ? [.process] : page == "persistence" ? [.persistence] : page == "hardware" ? [.hardware] : page == "extensions" ? [.extensions] : page == "applications" ? [.application] : []
            lines.append("\(page.uppercased()) / last seen is not guaranteed current presence")
            let records = view.inventory.filter { classes.isEmpty || classes.contains($0.observation.eventClass) }
            lines += records.map { "\($0.baselineStatus.rawValue) \($0.observation.component) LAST \(TimeText.iso($0.lastSeen))\($0.present ? "" : " ABSENT")" }
        }
        let footer = [String(repeating: "-", count: w), "[f] findings [e] events [n] network [p] processes [b] baseline", "[c] coverage [d] doctor [x] explain [o] overview [j/k] scroll [q] quit", "tripwire> _"]
        let top = ascii ? "+" : "┌", bottom = ascii ? "+" : "└", rightTop = ascii ? "+" : "┐", rightBottom = ascii ? "+" : "┘", bar = ascii ? "-" : "─", side = ascii ? "|" : "│"
        let capacity = max(2, height - footer.count - 2)
        let chosen = Array(lines.prefix(capacity)) + footer
        let rows = chosen.map { line -> String in
            // Preserve canonical static Unicode logo only; sanitize every dynamic row.
            if showArtwork && !ascii && artwork.contains(line) {
                let cut = String(line.prefix(w)); return side + " " + cut + String(repeating: " ", count: max(0, w - cut.count)) + " " + side
            }
            return side + " " + TerminalText.fit(line, width: w, ascii: ascii) + " " + side
        }
        return ([top + String(repeating: bar, count: w + 2) + rightTop] + rows + [bottom + String(repeating: bar, count: w + 2) + rightBottom]).joined(separator: "\n")
    }
    public static func eventLine(_ e: EvidenceEvent) -> String { "\(TimeText.iso(e.timestamp).suffix(9).prefix(8)) \(e.observation.eventClass.rawValue) \(e.baselineStatus.rawValue) \(e.observation.component) [\(e.id.prefix(8))]" }
}

public final class InteractiveConsole {
    public let store: EventStore
    public init(store: EventStore) { self.store = store }
    public func run(ascii: Bool) throws {
        #if os(Windows)
        try runWindows(ascii: ascii)
        #else
        guard isatty(STDOUT_FILENO) != 0, isatty(STDIN_FILENO) != 0, ProcessInfo.processInfo.environment["TERM"] != "dumb" else {
            print(ConsoleRenderer.render(try StoreView(store: store), ascii: true)); return
        }
        let shutdown = ConsoleShutdown()
        let previousTERM = signal(SIGTERM, SIG_IGN)
        let previousHUP = signal(SIGHUP, SIG_IGN)
        let termSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())
        let hupSource = DispatchSource.makeSignalSource(signal: SIGHUP, queue: .global())
        for source in [termSource, hupSource] { source.setEventHandler { shutdown.request() }; source.resume() }
        defer { termSource.cancel(); hupSource.cancel(); signal(SIGTERM, previousTERM); signal(SIGHUP, previousHUP) }
        var original = termios(); tcgetattr(STDIN_FILENO, &original)
        var raw = original; raw.c_lflag &= ~tcflag_t(ICANON | ECHO | ISIG)
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw)
        print("\u{1B}[?1049h\u{1B}[?25l", terminator: "")
        defer { tcsetattr(STDIN_FILENO, TCSAFLUSH, &original); print("\u{1B}[?25h\u{1B}[?1049l", terminator: ""); fflush(stdout) }
        var page = "overview", selection = 0, offset = 0, previous = ""
        while !shutdown.requested {
            var size = winsize(); _ = ioctl(STDOUT_FILENO, UInt(TIOCGWINSZ), &size)
            let width = size.ws_col > 0 ? Int(size.ws_col) : 80, height = size.ws_row > 0 ? Int(size.ws_row) : 24
            let view = try StoreView(store: store)
            selection = min(selection, max(0, view.findings.count - 1))
            let screen: String
            if page == "explain", !view.findings.isEmpty {
                let f = view.findings[selection]
                let evidence = try f.eventIDs.compactMap { try store.event(id: $0) }
                let lines = Explain.text(f, events: evidence).components(separatedBy: "\n").flatMap { line -> [String] in
                    let s = TerminalText.safe(line), n = max(10, width - 2)
                    if s.isEmpty { return [""] }; return stride(from: 0, to: s.count, by: n).map { String(s.dropFirst($0).prefix(n)) }
                }
                offset = min(offset, max(0, lines.count - 3))
                screen = (Array(lines.dropFirst(offset).prefix(max(1, height - 2))) + ["[j/k] scroll [f] findings [o] overview [q] quit"]).joined(separator: "\n")
            } else {
                let expanded = ConsoleRenderer.render(view, width: width, height: page == "overview" ? height : 10000, ascii: ascii, page: page, selection: selection).components(separatedBy: "\n")
                offset = min(offset, max(0, expanded.count - height))
                screen = expanded.dropFirst(offset).prefix(height).joined(separator: "\n")
            }
            if screen != previous { print("\u{1B}[H\u{1B}[2J" + screen, terminator: ""); fflush(stdout); previous = screen }
            var descriptor = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN), revents: 0)
            if poll(&descriptor, 1, 1000) > 0 {
                var byte: UInt8 = 0
                guard read(STDIN_FILENO, &byte, 1) == 1 else { return }
                if byte == 3 || byte == 4 || byte == 113 { return }
                let key = String(UnicodeScalar(byte))
                if key == "j" { if page == "findings" { selection += 1 }; offset += 1 }
                else if key == "k" { if page == "findings" { selection = max(0, selection - 1) }; offset = max(0, offset - 1) }
                else if let next = ["f": "findings", "e": "events", "n": "network", "p": "processes", "b": "baseline", "c": "coverage", "d": "doctor", "x": "explain", "o": "overview"][key] { page = next; offset = 0 }
            }
        }
        #endif
    }
    #if os(Windows)
    private func runWindows(ascii: Bool) throws {
        guard tw_isatty(0) != 0, tw_isatty(1) != 0, tw_console_begin() == 0 else {
            print(ConsoleRenderer.render(try StoreView(store: store), ascii: true)); return
        }
        defer { print("\u{1B}[?25h\u{1B}[?1049l", terminator: ""); fflush(nil); tw_console_end() }
        print("\u{1B}[?1049h\u{1B}[?25l", terminator: "")
        var page = "overview", selection = 0, offset = 0, previous = ""
        while true {
            var width: Int32 = 80, height: Int32 = 24; tw_console_size(&width, &height)
            let view = try StoreView(store: store)
            selection = min(selection, max(0, view.findings.count - 1))
            let lines: [String]
            if page == "explain", !view.findings.isEmpty {
                let finding = view.findings[selection]
                let evidence = try finding.eventIDs.compactMap { try store.event(id: $0) }
                lines = Explain.text(finding, events: evidence).components(separatedBy: "\n").map(TerminalText.safe)
            } else {
                lines = ConsoleRenderer.render(view, width: Int(width), height: page == "overview" ? Int(height) : 10000, ascii: ascii, page: page, selection: selection).components(separatedBy: "\n")
            }
            offset = min(offset, max(0, lines.count - Int(height)))
            let screen = lines.dropFirst(offset).prefix(Int(height)).joined(separator: "\n")
            if screen != previous { print("\u{1B}[H\u{1B}[2J" + screen, terminator: ""); fflush(nil); previous = screen }
            let byte = tw_console_key(1000)
            if byte == -2 || [3, 4, 113].contains(byte) { return }
            if byte == 106 { if page == "findings" { selection += 1 }; offset += 1 }
            else if byte == 107 { if page == "findings" { selection = max(0, selection - 1) }; offset = max(0, offset - 1) }
            else if let next = [102: "findings", 101: "events", 110: "network", 112: "processes", 98: "baseline", 99: "coverage", 100: "doctor", 120: "explain", 111: "overview"][Int(byte)] { page = next; offset = 0 }
        }
    }
    #endif
}

private final class ConsoleShutdown {
    private let lock = NSLock()
    private var value = false
    var requested: Bool { lock.lock(); defer { lock.unlock() }; return value }
    func request() { lock.lock(); value = true; lock.unlock() }
}

public enum TerminalRuntime {
    public static var isOutputTerminal: Bool {
        #if os(Windows)
        return tw_isatty(1) != 0
        #else
        return isatty(STDOUT_FILENO) != 0
        #endif
    }
}
