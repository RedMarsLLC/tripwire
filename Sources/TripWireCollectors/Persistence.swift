import Foundation
import TripWireCore

public struct PersistenceCollector: Collector {
    public let descriptor = SensorDescriptor("persistence", "Persistence files", source: "Foundation filesystem metadata, CryptoKit SHA-256, PropertyListSerialization, Security", monitors: "Current user's and system launch items, helpers, shell startup files and scheduled-execution directories", limitations: ["File presence does not establish launchd registration, enabled state or execution.", "Other users' homes, protected files and live background/login item databases are outside scope.", "Only plist executable target is retained; arguments, environment and file contents are not stored.", "Changes that occur between polls may be missed. Symlink targets are recorded but not followed.", "Browser extension activation, crontab registration and configuration profiles are not inferred from files."])
    public let home: URL
    public init(home: URL = FileManager.default.homeDirectoryForCurrentUser) { self.home = home }
    public static func inspectMetadata(_ url: URL) throws -> SafeFile.Inspection {
        do { return try SafeFile.inspect(url, hash: true) }
        catch {
            var metadata = try SafeFile.metadata(url, hash: false)
            metadata["hash"] = "NOT OBSERVABLE (content unavailable or changed during read)"
            return SafeFile.Inspection(metadata: metadata, data: nil)
        }
    }
    public func collect() async -> CollectorSnapshot {
        let fm = FileManager.default
        let directories = [home.appendingPathComponent("Library/LaunchAgents"), URL(fileURLWithPath: "/Library/LaunchAgents"), URL(fileURLWithPath: "/Library/LaunchDaemons"), URL(fileURLWithPath: "/Library/PrivilegedHelperTools"), URL(fileURLWithPath: "/etc/periodic/daily"), URL(fileURLWithPath: "/etc/periodic/weekly"), URL(fileURLWithPath: "/etc/periodic/monthly")]
        var urls: [URL] = [], failures = 0, partialHashes = 0, issues: [String] = []
        for directory in directories {
            do {
                let attrs = try fm.attributesOfItem(atPath: directory.path)
                if attrs[.type] as? FileAttributeType == .typeSymbolicLink {
                    urls.append(directory); failures += 1; issues.append("Symlinked directory not traversed: " + directory.path)
                } else { urls += try fm.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil).filter { !$0.lastPathComponent.hasPrefix(".") } }
            }
            catch { if !SafeFile.isMissing(error) { failures += 1; issues.append("Unavailable directory: " + directory.path) } }
        }
        let files = [".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bash_profile", ".bashrc", ".profile"].map { home.appendingPathComponent($0) } + ["/etc/zshrc", "/etc/zprofile", "/etc/zshenv", "/etc/profile", "/etc/crontab"].map { URL(fileURLWithPath: $0) }
        for file in files {
            do { _ = try fm.attributesOfItem(atPath: file.path); urls.append(file) }
            catch { if !SafeFile.isMissing(error) { failures += 1; issues.append("Unavailable metadata: " + file.path) } }
        }
        var observations: [Observation] = []
        for url in urls {
            do {
                let inspected = try Self.inspectMetadata(url)
                var attrs = inspected.metadata
                if attrs["hash"] != nil { partialHashes += 1 }
                if url.pathExtension == "plist", let data = inspected.data {
                    if let plist = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any] {
                        attrs["label"] = plist["Label"] as? String ?? "UNKNOWN"
                        let target = (plist["Program"] as? String) ?? (plist["ProgramArguments"] as? [String])?.first
                        if let target {
                            // Arbitrary command arguments may contain secrets. Only absolute executable paths are retained.
                            attrs["executable"] = target.hasPrefix("/") ? target : "UNKNOWN (relative executable)"
                            if target.hasPrefix("/") {
                                let identity = Signature.identity(target)
                                attrs["targetTeamID"] = identity.teamID ?? "UNKNOWN"
                                attrs["targetSignature"] = identity.signatureStatus ?? "UNKNOWN"
                            }
                        }
                        attrs["disabledInPlist"] = (plist["Disabled"] as? Bool).map(String.init) ?? "UNSPECIFIED"
                    } else { attrs["plistParsing"] = "UNKNOWN (unrecognized format; hash/metadata retained)" }
                }
                observations.append(Observation(key: url.path, eventClass: .persistence, component: url.path, attributes: attrs, limitations: descriptor.limitations + (attrs["hash"] == nil ? [] : ["Content hash unavailable; metadata only. No conclusion about file contents."]), confidence: attrs["hash"] == nil ? .high : .moderate))
            } catch { failures += 1; issues.append("Unavailable file: " + url.path + " (" + String((error as NSError).code) + ")") }
        }
        return CollectorSnapshot(descriptor: descriptor, observations: observations, complete: failures == 0, state: .degraded, detail: "\(observations.count) file records; \(failures) unreadable inventory sources; \(partialHashes) unavailable content hashes. Registered login/background items NOT OBSERVABLE. " + issues.joined(separator: "; "))
    }
}

public struct CanaryCollector: Collector {
    public let descriptor = SensorDescriptor("canaries", "Local canary markers", source: "Foundation filesystem metadata + SHA-256", monitors: "Only user-enrolled marker files", limitations: ["Polling detects marker modification/removal, not reads or accesses.", "Responsible process is UNKNOWN without an event source.", "No network listener or vulnerable service is created."])
    public let directory: URL
    public init(directory: URL) { self.directory = directory }
    public func collect() async -> CollectorSnapshot {
        do {
            try SafeFile.requirePrivateDirectory(directory)
            let urls = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil).filter { $0.pathExtension == "marker" }
            let observations = try urls.map { url in Observation(key: url.path, eventClass: .canary, component: url.lastPathComponent, attributes: try SafeFile.metadata(url, hash: true), limitations: descriptor.limitations) }
            return CollectorSnapshot(descriptor: descriptor, observations: observations, complete: true, state: .active, visibility: .limited, detail: "\(observations.count) enrolled markers. Reads are NOT OBSERVABLE.")
        } catch { return CollectorSnapshot(descriptor: descriptor, state: .stopped, visibility: .unavailable, detail: "No canary directory or directory unreadable; create an opt-in marker with canary create NAME") }
    }
}
