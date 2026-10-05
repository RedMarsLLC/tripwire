import AppKit
import Combine
import Darwin
import Foundation
import Security
import CTripWireFileAuthorization
import TripWireCore
import TripWireCollectors

final class FileMonitorStopToken: @unchecked Sendable {
    private let lock = NSLock()
    private var requested = false
    var stopped: Bool { lock.lock(); defer { lock.unlock() }; return requested }
    func request() { lock.lock(); requested = true; lock.unlock() }
}

enum FileMonitorPhase: Equatable {
    case stopped, authorizing, waiting, reporting, stopping, failed
    var active: Bool { [.authorizing, .waiting, .reporting, .stopping].contains(self) }
}

/// Codes are produced only by the bundled launcher. Raw stderr is never displayed.
enum FileHelperStatus: String {
    case started = "STARTED", stopped = "STOPPED", permission = "FULL_DISK_ACCESS_REQUIRED"
    case launch = "LAUNCH_FAILED", exited = "TOOL_EXITED", pipe = "PIPE_FAILED"
    case backpressure = "BACKPRESSURE", unresponsive = "APP_UNRESPONSIVE"
    static let prefix = "TRIPWIRE-HELPER/1 "
    static func parse(_ data: Data) -> Self? {
        guard data.count <= 128, let value = String(data: data, encoding: .utf8), value.hasPrefix(prefix) else { return nil }
        return Self(rawValue: String(value.dropFirst(prefix.count)))
    }
    var explanation: String {
        switch self {
        case .started: return "Helper started. Waiting for a valid file-event report; visibility is not established yet."
        case .stopped: return "File monitoring stopped. Previous findings are retained."
        case .permission: return "macOS denied the event source. Enable Full Disk Access for TripWire in System Settings, quit and reopen TripWire, then start file monitoring again. If macOS identifies eslogger as the responsible tool, authorize /usr/bin/eslogger instead."
        case .launch: return "The helper could not start /usr/bin/eslogger. File events are unavailable on this system."
        case .exited: return "The macOS event source exited. File events are no longer being monitored. Check Full Disk Access, then retry."
        case .pipe: return "The file-event connection failed. Coverage is interrupted; retry file monitoring."
        case .backpressure: return "TripWire could not drain the event buffer for eight seconds. Monitoring stopped; missed activity is unknown. Retry file monitoring."
        case .unresponsive: return "TripWire stopped responding to the helper. The helper stopped the event source; coverage is interrupted."
        }
    }
}

@MainActor final class FileMonitorController: ObservableObject {
    @Published private(set) var phase: FileMonitorPhase = .stopped
    @Published private(set) var detail = "Enable file monitoring here. No terminal or developer account is needed. macOS will ask for administrator approval; Full Disk Access is also required."
    private var stopToken: FileMonitorStopToken?
    private var task: Task<Void, Never>?
    private(set) var enabledForSession = false

    func start(storeURL: URL) {
        guard !phase.active else { return }
        enabledForSession = true
        let stop = FileMonitorStopToken(); stopToken = stop
        phase = .authorizing; detail = "Approve the macOS administrator dialog to start the session helper. Your password is handled by macOS."
        let bundleURL = Bundle.main.bundleURL
        task = Task {
            let failure = await Task.detached(priority: .utility) {
                await ManagedFileSession.run(bundleURL: bundleURL, storeURL: storeURL, stop: stop) { phase, detail in
                    Task { @MainActor [weak self] in
                        guard self?.stopToken === stop, self?.phase != .stopping else { return }
                        self?.phase = phase; self?.detail = detail
                    }
                }
            }.value
            guard stopToken === stop else { return }
            stopToken = nil; task = nil
            phase = failure == nil ? .stopped : .failed
            detail = failure ?? FileHelperStatus.stopped.explanation
        }
    }
    func stop() {
        guard phase.active else { return }
        phase = .stopping; detail = "Stopping the file-event source and recording the interruption…"
        stopToken?.request()
    }
    deinit { stopToken?.request() }
    func openPrivacySettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") { NSWorkspace.shared.open(url) }
    }
}

enum ManagedFileSession {
    /// Authorization Services supplies a private bidirectional pipe. This local
    /// compatibility path needs no Apple-issued identity or persistent service.
    /// The launch API is deprecated; isolate it here, never treat it as the
    /// production native ES deployment, and surface an unavailable result.
    private static func authorize(bundleURL: URL) throws -> UnsafeMutablePointer<FILE> {
        guard bundleURL.pathExtension == "app" else { throw TripWireError.message("Open the packaged TripWire.app to use its bundled file monitor.") }
        let helper = bundleURL.appendingPathComponent("Contents/Helpers/TripWireFileHelper")
        for url in [bundleURL, helper] {
            var code: SecStaticCode?
            guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code,
                  SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate), nil) == errSecSuccess else {
                throw TripWireError.message("TripWire or its bundled helper failed code-signature validation. Rebuild or reinstall the app before granting administrator access.")
            }
        }
        var authorization: AuthorizationRef?
        let created = AuthorizationCreate(nil, nil, [], &authorization)
        guard created == errAuthorizationSuccess, let authorization else { throw TripWireError.message("macOS authorization is unavailable (\(created)).") }
        defer { AuthorizationFree(authorization, []) }
        let name = strdup(kAuthorizationRightExecute)!
        defer { free(name) }
        var right = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
        let approval = withUnsafeMutablePointer(to: &right) { item in
            var rights = AuthorizationRights(count: 1, items: item)
            return AuthorizationCopyRights(authorization, &rights, nil, [.interactionAllowed, .extendRights, .preAuthorize], nil)
        }
        guard approval == errAuthorizationSuccess else {
            throw TripWireError.message(approval == errAuthorizationCanceled ? "Administrator approval was cancelled. File monitoring remains off." : "macOS denied administrator authorization (\(approval)). File monitoring remains off.")
        }
        var channel: UnsafeMutablePointer<FILE>?
        let result = helper.path.withCString { TripWireLaunchFileHelper(authorization, $0, &channel) }
        guard result == errAuthorizationSuccess, let channel else {
            if result == errAuthorizationCanceled { throw TripWireError.message("Administrator approval was cancelled. File monitoring remains off.") }
            throw TripWireError.message("macOS could not authorize the session helper (\(result)). File monitoring remains off; no service was installed.")
        }
        return channel
    }

    static func run(bundleURL: URL, storeURL: URL, stop: FileMonitorStopToken, launch: (URL) throws -> UnsafeMutablePointer<FILE> = authorize, update: @escaping (FileMonitorPhase, String) -> Void) async -> String? {
        do {
            if stop.stopped { return nil }
            let store = try EventStore(url: storeURL)
            // Acquire before prompting: an existing terminal/app receiver owns
            // this same lock. Never start duplicate sources or disturb its state.
            let owner = try CollectorOwnerLock(url: storeURL.appendingPathExtension("file-events"))
            defer { withExtendedLifetime(owner) {} }
            if stop.stopped { return nil }
            let channel = try launch(bundleURL)
            defer { fclose(channel) }
            let fd = fileno(channel)
            _ = fcntl(fd, F_SETNOSIGPIPE, 1)
            guard fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == 0 else { throw TripWireError.message("Could not configure the private helper connection.") }
            if stop.stopped { return nil }
            let bridge = OpenEventBridge(store: store, managed: true)
            var failure: String?
            defer { try? bridge.stop(reason: failure, failed: failure != nil) }
            do {
                var framer = BoundedLineFramer(), refreshed = Date.distantPast
                var pulse: UInt8 = 72, lastPulse = Date.distantPast
                var bytes = [UInt8](repeating: 0, count: 32768)
                var started = false
                update(.waiting, "Starting the bundled event source; waiting for a valid report.")
                while !stop.stopped {
                    if Date().timeIntervalSince(lastPulse) >= 2 {
                        guard write(fd, &pulse, 1) == 1 else { throw TripWireError.message("The helper connection closed. File monitoring is off.") }
                        lastPulse = Date()
                    }
                    if Date().timeIntervalSince(refreshed) >= 2 {
                        try await bridge.refresh(); refreshed = Date()
                        let health = try store.sensors().first { $0.id == OpenEventBridge.id }
                        let current = health?.lastSuccess.map { Date().timeIntervalSince($0) < 10 } ?? false
                        update(current ? .reporting : .waiting, current ? "File events are reporting for enabled boundaries. Diagnostic source; coverage remains limited." : "Waiting for recent valid file events. A running helper alone does not establish coverage.")
                    }
                    var pollFD = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
                    let ready = poll(&pollFD, 1, 250)
                    if ready < 0 { if errno == EINTR { continue }; throw TripWireError.message(FileHelperStatus.pipe.explanation) }
                    if ready == 0 { continue }
                    let count = read(fd, &bytes, bytes.count)
                    if count < 0 { if errno == EINTR || errno == EAGAIN { continue }; throw TripWireError.message(FileHelperStatus.pipe.explanation) }
                    if count == 0 { throw TripWireError.message(started ? FileHelperStatus.exited.explanation : "The bundled helper exited before starting. File events are unavailable; retry authorization or rebuild the app.") }
                    try framer.consume(Data(bytes.prefix(count))) { data in
                        if data.isEmpty { return }
                        if let status = FileHelperStatus.parse(data) {
                            if status == .started { started = true; return }
                            throw TripWireError.message(status.explanation)
                        }
                        guard started else { throw TripWireError.message("Unrecognized helper startup response. File monitoring is off.") }
                        try bridge.consume(data)
                    }
                }
                var end: UInt8 = 83; _ = write(fd, &end, 1)
                // Closing the private pipe also stops the helper; its 10-second
                // lease covers an app crash or a stalled event-processing thread.
            } catch { failure = String(describing: error) }
            return stop.stopped ? nil : failure
        } catch { return stop.stopped ? nil : String(describing: error) }
    }
}
