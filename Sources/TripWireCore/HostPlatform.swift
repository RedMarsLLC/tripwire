import Foundation

public enum HostPlatform: String, Codable, CaseIterable {
    case macOS, linux, windows
    public static var current: Self {
        #if os(macOS)
        return .macOS
        #elseif os(Windows)
        return .windows
        #else
        return .linux
        #endif
    }
    public var displayName: String { self == .macOS ? "macOS" : self == .linux ? "Linux" : "Windows" }
    public static var defaultStoreURL: URL {
        let home = FileManager.default.homeDirectoryForCurrentUser
        switch current {
        case .macOS: return home.appendingPathComponent("Library/Application Support/TripWire/events.sqlite")
        case .linux:
            // The application's own path setting, never a monitored process environment.
            let state = ProcessInfo.processInfo.environment["XDG_STATE_HOME"]
            let root = state.flatMap { $0.hasPrefix("/") ? URL(fileURLWithPath: $0) : nil } ?? home.appendingPathComponent(".local/state")
            return root.appendingPathComponent("tripwire/events.sqlite")
        case .windows:
            let root = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first ?? home.appendingPathComponent("AppData/Local")
            return root.appendingPathComponent("TripWire/events.sqlite")
        }
    }
}
