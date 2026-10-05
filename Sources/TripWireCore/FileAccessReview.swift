import Foundation

/// Path-based review hints, not content inspection or a claim about intent.
public enum FileAccessReview {
    public static func reason(path: String, home: String, platform: HostPlatform = .current) -> String? {
        // libproc paths are absolute. Normalize lexical components without resolving/reading a target.
        let path = lexicalPath(platform == .windows ? path.replacingOccurrences(of: "\\", with: "/").lowercased() : path)
        let home = lexicalPath(platform == .windows ? home.replacingOccurrences(of: "\\", with: "/").lowercased() : home)
        let credentialRoots = [".ssh", ".aws", ".azure", ".config/gcloud", ".kube", ".gnupg"] + (platform == .macOS ? ["Library/Keychains"] : [])
        if credentialRoots.contains(where: { within(path, home + "/" + $0) }) {
            return "Credential location: this path can contain credentials, keys or account configuration. Review whether the associated app should have it open."
        }
        if (platform == .macOS && ["/Library/LaunchAgents", "/Library/LaunchDaemons", home + "/Library/LaunchAgents"].contains(where: { within(path, $0) })) ||
            [".zshrc", ".zprofile", ".bashrc", ".bash_profile", ".profile"].contains(where: { path == home + "/" + $0 }) {
            return "Startup location: files here can affect what runs automatically. An open file does not establish a startup change or execution."
        }
        if platform == .macOS && ["/Library/Extensions", "/Library/SystemExtensions"].contains(where: { within(path, $0) }) {
            return "Extension location: files here may belong to privileged extensions. An open file does not establish installation or kernel loading."
        }
        if platform == .linux {
            if ["/etc/systemd", "/usr/lib/systemd", "/etc/cron.d", "/etc/init.d", home + "/.config/systemd", home + "/.config/autostart"].contains(where: { within(path, $0) }) {
                return "Startup location: observed access can affect automatic execution. No execution or modification is inferred."
            }
            if ["/lib/modules", "/usr/lib/modules", "/etc/modprobe.d", "/etc/modules-load.d"].contains(where: { within(path, $0) }) {
                return "Kernel-module location: review access; this does not establish installation or loading."
            }
        }
        if platform == .windows {
            if [home + "/appdata/roaming/microsoft/credentials", home + "/appdata/local/microsoft/credentials"].contains(where: { within(path, $0) }) {
                return "Credential location: review whether this app should access it. Contents were not read."
            }
            if within(path, home + "/appdata/roaming/microsoft/windows/start menu/programs/startup") {
                return "Startup location: review access; automatic execution is not established."
            }
        }
        return nil
    }
    private static func lexicalPath(_ value: String) -> String {
        var parts: [Substring] = []
        for part in value.split(separator: "/") {
            if part == ".." { if !parts.isEmpty { parts.removeLast() } }
            else if part != "." { parts.append(part) }
        }
        return "/" + parts.joined(separator: "/")
    }
    private static func within(_ path: String, _ root: String) -> Bool { path == root || path.hasPrefix(root + "/") }

    public static func finding(_ event: EvidenceEvent) -> Finding? {
        guard event.sourceCollector == "ai-open-files", event.observation.eventClass == .file,
              ["INITIAL", "NEW", "CHANGED"].contains(event.eventType),
              event.previousState != event.currentState,
              event.observation.attributes["associatedApp"] != nil,
              let reason = event.observation.attributes["reviewReason"] else { return nil }
        let attrs = event.observation.attributes
        return Finding(timestamp: event.timestamp, title: "AI-associated process holds a file in a sensitive location",
            whatHappened: "\(attrs["associatedApp"] ?? "Recognized app")-associated process \(attrs["pid"] ?? "UNKNOWN") was observed holding \(event.observation.component) open. Mode: \(attrs["openMode"] ?? "UNKNOWN").",
            whyFlagged: reason + " This flags the observed location even on the first check; existing access is not automatically trusted. It does not establish an unauthorized action or malicious intent.",
            component: event.observation.component, eventIDs: [event.id], baselineDifference: "Sensitive-location review is independent of baseline approval. " + (attrs["associationBasis"] ?? "Association basis unknown"),
            confidence: event.observation.confidence, severity: .notice,
            limitations: Array(Set(event.limitations + event.observation.limitations)).sorted(),
            suggestedInvestigation: ["Check the associated app, holding executable, PID and observation time against work you authorized.", "Open mode is capability; an inherited descriptor or routine app operation may explain this observation. No file contents were collected.", "Use an approved OS event collector to investigate short-lived access and process ancestry. Do not infer a read, write, secret disclosure or AI instruction from this snapshot alone."],
            ruleID: "ai-sensitive-open-file-v1")
    }
}
