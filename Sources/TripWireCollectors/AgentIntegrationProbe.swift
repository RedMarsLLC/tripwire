import Foundation
import Darwin
import TripWireCore

/// Bounded read-only inspection of default hook config. Retains only matching
/// event names, never commands, other configuration fields or tool payloads.
public enum AgentIntegrationProbe {
    public static var defaultExecutable: URL {
        let bundle = Bundle.main.bundleURL
        if bundle.pathExtension == "app" { return bundle.deletingLastPathComponent().appendingPathComponent("tripwire") }
        return URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().appendingPathComponent("tripwire")
    }
    public static func inspect(home: URL = FileManager.default.homeDirectoryForCurrentUser, executable: URL) -> [AgentSourceSetup] {
        AgentProvider.allCases.map { provider in
            let relative: String
            switch provider {
            case .codex: relative = ".codex/hooks.json"
            case .claudeCode: relative = ".claude/settings.json"
            case .cursor: relative = ".cursor/hooks.json"
            case .generic: return AgentSourceSetup(provider: provider, state: .external)
            }
            let url = home.appendingPathComponent(relative)
            let descriptor = open(url.path, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW)
            guard descriptor >= 0 else {
                return AgentSourceSetup(provider: provider, state: errno == ENOENT ? .notFound : .unreadable)
            }
            let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
            defer { try? file.close() }
            var metadata = stat()
            guard fstat(descriptor, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFREG,
                  metadata.st_size <= 1_048_576 else { return AgentSourceSetup(provider: provider, state: .unreadable) }
            do {
                let data = try file.read(upToCount: 1_048_577) ?? Data()
                guard data.count <= 1_048_576,
                      let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                    return AgentSourceSetup(provider: provider, state: .unreadable)
                }
                guard let hooks = root["hooks"] as? [String: Any] else {
                    return AgentSourceSetup(provider: provider, state: root["hooks"] == nil ? .notFound : .unreadable)
                }
                let commands = [executable.path, "\"\(executable.path)\"", "'\(executable.path.replacingOccurrences(of: "'", with: "'\\''"))'"]
                    .flatMap { path in provider == .codex ? [path + " agent-hook", path + " agent-hook --provider codex"] : [path + " agent-hook --provider " + provider.rawValue] }
                func matches(_ entry: [String: Any]) -> Bool {
                    guard let command = entry["command"] as? String else { return false }
                    return commands.contains(command.trimmingCharacters(in: .whitespacesAndNewlines))
                }
                let events = hooks.compactMap { event, value -> String? in
                    guard event.count <= 64, event.unicodeScalars.allSatisfy(CharacterSet.alphanumerics.contains),
                          let entries = value as? [[String: Any]] else { return nil }
                    let found = entries.contains { entry in
                        if provider == .cursor { return matches(entry) }
                        return (entry["hooks"] as? [[String: Any]])?.contains(where: matches) == true
                    }
                    return found ? event : nil
                }.sorted()
                return AgentSourceSetup(provider: provider, state: events.isEmpty ? .notFound : .entriesFound, events: events)
            } catch {
                return AgentSourceSetup(provider: provider, state: .unreadable)
            }
        }
    }
}
