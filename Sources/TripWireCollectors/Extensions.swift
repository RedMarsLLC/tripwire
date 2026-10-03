import Foundation
import TripWireCore

public enum ExtensionParser {
    public static func parse(_ text: String) -> (observations: [Observation], recognized: Bool) {
        let regex = try! NSRegularExpression(pattern: #"^\s*(?:\*\s+)*(\S+)\s+(\S+)\s+\(([^)]+)\)\s+(.+)\[([^]]+)\]\s*$"#)
        var observations: [Observation] = [], invalid = false
        var declaredCount: Int?
        for line in text.split(separator: "\n").map(String.init) {
            if line.range(of: #"^\d+ extension\(s\)$"#, options: .regularExpression) != nil { declaredCount = Int(line.split(separator: " ").first ?? ""); continue }
            if line.hasPrefix("---") || line.contains("teamID") || line.trimmingCharacters(in: .whitespaces).isEmpty { continue }
            guard let m = regex.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)) else { invalid = true; continue }
            func value(_ i: Int) -> String { String(line[Range(m.range(at: i), in: line)!]) }
            observations.append(Observation(key: value(2), eventClass: .extensions, component: value(2), attributes: ["teamID": value(1), "bundleID": value(2), "version": value(3), "state": value(5), "installationPath": "UNKNOWN", "source": "systemextensionsctl list"], limitations: ["Reported activation state does not prove healthy operation."]))
        }
        return (observations, declaredCount == observations.count && Set(observations.map(\.key)).count == observations.count && !invalid)
    }
}
public struct ExtensionCollector: Collector {
    public let descriptor = SensorDescriptor("extensions", "System / DriverKit extensions", source: "systemextensionsctl(8) list", monitors: "System extension registrations, Team IDs, versions and activation state", limitations: ["Diagnostic output is version-dependent; unexpected formats fail closed.", "Installation path and runtime health are not exposed by this source.", "Built-in drivers and loaded kernel extensions are outside this sensor's scope."])
    public init() {}
    public func collect() async -> CollectorSnapshot {
        let result = ReadCommand.run("/usr/bin/systemextensionsctl", ["list"])
        let parsed = ExtensionParser.parse(result.text)
        let valid = result.successful && result.error.isEmpty && parsed.recognized
        return CollectorSnapshot(descriptor: descriptor, observations: parsed.observations, complete: valid, state: valid ? .active : .error, visibility: valid ? .limited : .unknown, detail: valid ? "\(parsed.observations.count) registered system extensions" : "Registration inventory unavailable or format unrecognized")
    }
}
public struct KernelBundleCollector: Collector {
    public let descriptor = SensorDescriptor("kernel-bundles", "Third-party kernel bundles", source: "Foundation bundle metadata, Security signing metadata", monitors: "Installed .kext bundles in /Library/Extensions", limitations: ["Installed bundle does not establish loaded state.", "System kernel collections and built-in drivers are outside this inventory."])
    public init() {}
    public func collect() async -> CollectorSnapshot {
        do {
            let urls = try FileManager.default.contentsOfDirectory(at: URL(fileURLWithPath: "/Library/Extensions"), includingPropertiesForKeys: nil).filter { $0.pathExtension == "kext" }
            var failed = 0
            let observations = urls.compactMap { url -> Observation? in
                guard let bundle = Bundle(url: url) else { failed += 1; return nil }
                let signature = Signature.identity(url.path)
                return Observation(key: url.path, eventClass: .extensions, component: bundle.bundleIdentifier ?? url.lastPathComponent, attributes: ["path": url.path, "bundleID": bundle.bundleIdentifier ?? "UNKNOWN", "version": bundle.infoDictionary?["CFBundleVersion"] as? String ?? "UNKNOWN", "teamID": signature.teamID ?? "UNKNOWN", "signingIdentity": signature.signingIdentity ?? "UNKNOWN", "loadedState": "NOT OBSERVABLE"], limitations: descriptor.limitations)
            }
            return CollectorSnapshot(descriptor: descriptor, observations: observations, complete: failed == 0, state: .degraded, detail: "Installed bundle metadata only; loaded state NOT OBSERVABLE")
        } catch { return CollectorSnapshot(descriptor: descriptor, state: .error, visibility: .unknown, detail: "Kernel bundle directory unreadable") }
    }
}
