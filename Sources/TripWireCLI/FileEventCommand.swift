#if os(macOS)
import Foundation
import Darwin
import TripWireCore
import TripWireCollectors

enum FileEventCommand {
    static func run(url: URL) async throws {
        guard getuid() != 0, isatty(STDIN_FILENO) == 0 else { throw TripWireError.message("Run the bridge as your normal user with eslogger JSONL piped into stdin. Only eslogger should use sudo. See docs/FILE_EVENTS.md.") }
        let store = try EventStore(url: url), bridge = OpenEventBridge(store: store)
        let owner = try CollectorOwnerLock(url: url.appendingPathExtension("file-events"))
        defer { withExtendedLifetime(owner) {}; try? bridge.stop() }
        let stop = StopToken()
        signal(SIGINT, SIG_IGN); signal(SIGTERM, SIG_IGN)
        let signals = [SIGINT, SIGTERM].map { DispatchSource.makeSignalSource(signal: $0, queue: .global()) }
        for signal in signals { signal.setEventHandler { stop.request() }; signal.resume() }
        defer { signals.forEach { $0.cancel() } }
        var framer = BoundedLineFramer(), refreshed = Date.distantPast
        while !stop.stopped {
            if Date().timeIntervalSince(refreshed) > 2 { try await bridge.refresh(); refreshed = Date() }
            var fd = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN), revents: 0)
            let ready = poll(&fd, 1, 500)
            if ready < 0 { if errno == EINTR { continue }; throw TripWireError.message("Open-event input failed") }
            if ready == 0 { continue }
            var bytes = [UInt8](repeating: 0, count: 32768)
            let count = read(STDIN_FILENO, &bytes, bytes.count)
            if count == 0 { try framer.finish(line: bridge.consume); return }
            if count < 0 { if errno == EINTR { continue }; throw TripWireError.message("Open-event input failed") }
            try framer.consume(Data(bytes.prefix(count)), line: bridge.consume)
        }
    }
}
#endif
