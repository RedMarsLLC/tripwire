import Foundation
import TripWireCore
import TripWireTerminal

enum TripwireCommands {
    static let usage = "tripwire tripwires [list | save --name NAME --path ABSOLUTE-PATH --kind file|folder|application [--id UUID] [--disabled] | enable UUID | disable UUID | delete UUID] [--json] [--db PATH]"
    static func run(_ arguments: [String], url: URL, json: Bool) throws {
        let command = arguments.first ?? "list"
        let rest = Array(arguments.dropFirst())
        switch command {
        case "list":
            guard rest.isEmpty else { throw TripWireError.message(usage) }
            let rules = try EventStore(url: url, access: .readOnly).tripwireRules()
            if json { print(String(decoding: try JSONEncoder.stable.encode(rules), as: UTF8.self)) }
            else {
                if rules.isEmpty { print("No tripwires configured. " + usage) }
                for rule in rules { print(TerminalText.safe("\(rule.id) · \(rule.enabled ? "ENABLED" : "DISABLED") · \(rule.name)\n\(rule.kind.rawValue): \(rule.path)\n\(rule.scopeDescription)")) }
            }
        case "save":
            var options = rest
            func take(_ key: String) throws -> String? {
                guard let i = options.firstIndex(of: key) else { return nil }
                guard i + 1 < options.count else { throw TripWireError.message(usage) }
                let value = options[i + 1]; options.removeSubrange(i...i + 1); return value
            }
            guard let name = try take("--name"), let path = try take("--path"), let kindText = try take("--kind"), let kind = TripwireKind(rawValue: kindText) else { throw TripWireError.message(usage) }
            let id = try take("--id") ?? UUID().uuidString
            let disabled = options == ["--disabled"]
            guard options.isEmpty || disabled else { throw TripWireError.message(usage) }
            let rule = try TripwireRule(id: id, name: name, path: path, kind: kind, enabled: !disabled).validated()
            try EventStore(url: url).saveTripwire(rule)
            print("Tripwire saved. It applies to future supported observations while monitoring is running.")
        case "enable", "disable", "delete":
            guard rest.count == 1, UUID(uuidString: rest[0]) != nil else { throw TripWireError.message(usage) }
            // Validate existence before opening a writer; a typo must not create a store.
            guard var rule = try EventStore(url: url, access: .readOnly).tripwireRules().first(where: { $0.id == rest[0] }) else { throw TripWireError.message("Tripwire not found") }
            let writer = try EventStore(url: url)
            if command == "delete" { try writer.deleteTripwire(id: rule.id) }
            else { rule.enabled = command == "enable"; try writer.saveTripwire(rule) }
            print("Tripwire \(command)d. Existing alerts and evidence are retained.")
        default: throw TripWireError.message(usage)
        }
    }
}
