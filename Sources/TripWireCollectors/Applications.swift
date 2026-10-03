import Foundation
import Darwin
import TripWireCore

/// A scoped inventory of application bundles, not an installation log or a file-access monitor.
public struct ApplicationCollector: Collector {
    public let descriptor: SensorDescriptor
    private let roots: [URL]
    private let entryLimit: Int
    private let bundleLimit: Int
    private let depthLimit: Int

    public init(roots: [URL] = [URL(fileURLWithPath: "/Applications"), FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications")], entryLimit: Int = 8192, bundleLimit: Int = 512, depthLimit: Int = 4) {
        self.roots = Array(Set(roots.map { $0.standardizedFileURL })).sorted { $0.path < $1.path }
        self.entryLimit = max(1, entryLimit); self.bundleLimit = max(1, bundleLimit); self.depthLimit = max(1, depthLimit)
        descriptor = SensorDescriptor("applications", "Installed applications", source: "Scoped directory inventory, bounded Info.plist and Security signing metadata",
            monitors: "Application bundles in plain folders under " + self.roots.map(\.path).joined(separator: ", ") + "; non-app symlinks excluded; folder depth \(self.depthLimit); entry limit \(self.entryLimit); bundle limit \(self.bundleLimit)",
            limitations: ["Only the declared application folders are inventoried; system apps, other users, downloads, package receipts and command-line packages are outside scope.",
                "App contents and nested bundles are not recursively inspected. Metadata changes do not cover every executable or resource modification.",
                "Signing metadata is not a validity check, trust verdict or proof that an application is wanted.",
                "Polling can miss changes between checks. Installation time and the responsible process or AI agent are UNKNOWN.",
                "Symlinks are not followed. Unreadable, changing or bounded inventories cannot establish absence."])
    }

    public func collect() async -> CollectorSnapshot {
        var observations: [Observation] = [], failures = 0, visited = 0, excludedLinks = 0, bounded = false
        var issues: [String] = []
        func issue(_ url: URL, _ reason: String) {
            failures += 1
            if issues.count < 6 { issues.append(String(url.path.prefix(512)) + ": " + reason) }
        }
        let deadline = ProcessInfo.processInfo.systemUptime + 12
        var directories: [(URL, String)] = []
        for root in roots {
            do {
                guard let state = try directoryState(root) else { continue }
                directories.append((root, state))
            } catch { issue(root, "Source folder unavailable or symlinked"); continue }
            guard let entries = FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isPackageKey], options: [], errorHandler: { url, error in issue(url, "Enumeration failed (\((error as NSError).code))"); return true }) else { issue(root, "Cannot enumerate source"); continue }
            while let url = entries.nextObject() as? URL {
                visited += 1
                guard visited <= entryLimit, observations.count < bundleLimit, ProcessInfo.processInfo.systemUptime < deadline else { bounded = true; break }
                do {
                    let metadata = try SafeFile.metadata(url, hash: false)
                    if url.pathExtension.lowercased() == "app" {
                        entries.skipDescendants()
                        let result = try application(url, metadata: metadata)
                        observations.append(result.observation)
                        if !result.complete { issue(url, "Application manifest unavailable, invalid or changed during scan") }
                    } else if metadata["type"] == FileAttributeType.typeSymbolicLink.rawValue {
                        entries.skipDescendants()
                        // Links (including documentation links) are outside the declared plain-folder
                        // scope. Without following them we cannot tell whether a former folder's apps
                        // are hidden, so retain their prior evidence and disable removal inference.
                        excludedLinks += 1
                    } else if metadata["type"] == FileAttributeType.typeDirectory.rawValue {
                        if (try url.resourceValues(forKeys: [.isPackageKey])).isPackage == true {
                            entries.skipDescendants()
                        } else if entries.level >= depthLimit {
                            entries.skipDescendants(); bounded = true
                        } else if let state = try directoryState(url) {
                            directories.append((url, state))
                        } else { issue(url, "Folder disappeared during scan") }
                    }
                } catch { entries.skipDescendants(); issue(url, "Entry metadata unavailable (\((error as NSError).code))") }
            }
            if visited > entryLimit || observations.count >= bundleLimit { bounded = true; break }
        }
        // Directory replacement/removal during enumeration cannot establish a complete inventory.
        for (url, before) in directories {
            if (try? directoryState(url)) != before { issue(url, "Folder changed or became unreadable during scan") }
        }
        let complete = failures == 0 && !bounded
        return CollectorSnapshot(descriptor: descriptor, observations: observations, complete: complete, absenceReliable: excludedLinks == 0,
            state: complete && excludedLinks == 0 ? .active : .degraded, visibility: .limited,
            detail: "\(observations.count) application bundle entries observed. " + (complete ? "Scoped metadata inventory completed." : "Partial inventory: \(failures) unreadable/changing entries\(bounded ? "; scan limit reached" : ""). Absence cannot be inferred. " + issues.joined(separator: "; ")) + (excludedLinks > 0 ? " \(excludedLinks) non-app symlink(s) excluded; linked folders are outside scope and removals cannot be inferred." : "") + " Responsible agent UNKNOWN; apps outside declared folders are not covered.")
    }

    private func application(_ url: URL, metadata: [String: String]) throws -> (observation: Observation, complete: Bool) {
        var values = metadata
        var complete = true
        values["responsibleAgent"] = "UNKNOWN (snapshot does not identify the actor)"
        values["bundleID"] = "UNKNOWN"; values["version"] = "UNKNOWN"; values["build"] = "UNKNOWN"
        values["signatureStatus"] = "UNKNOWN"; values["teamID"] = "UNKNOWN"
        var limitations = descriptor.limitations
        if metadata["type"] == FileAttributeType.typeSymbolicLink.rawValue {
            values["bundleMetadata"] = "NOT OBSERVABLE (symlink not followed)"
        } else if metadata["type"] == FileAttributeType.typeDirectory.rawValue {
            do {
                let contents = url.appendingPathComponent("Contents", isDirectory: true)
                guard let before = try directoryState(contents) else { throw TripWireError.message("Missing Contents folder") }
                // Avoid Bundle's metadata cache: an update at the same path must produce fresh values.
                let info = try SafeFile.inspect(contents.appendingPathComponent("Info.plist"), hash: true)
                guard let data = info.data, let plist = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { throw TripWireError.message("Unreadable or invalid application manifest") }
                let fields = ["CFBundleIdentifier": "bundleID", "CFBundleShortVersionString": "version", "CFBundleVersion": "build", "CFBundleName": "name"]
                for (key, field) in fields {
                    if let value = plist[key] as? String, !value.isEmpty, value.utf8.count <= 1024 { values[field] = value }
                }
                values["infoPlistSHA256"] = info.metadata["sha256"]
                let signing = Signature.identity(url.path)
                values["signatureStatus"] = signing.signatureStatus ?? "UNKNOWN"
                values["teamID"] = signing.teamID ?? "UNKNOWN"
                values["signingIdentity"] = signing.signingIdentity ?? "UNKNOWN"
                guard try directoryState(contents) == before, try SafeFile.metadata(url, hash: false) == metadata else { throw TripWireError.message("Application changed during inventory") }
            } catch {
                // Discard potentially mixed-version details; retain independently observed path metadata.
                values = metadata.merging(["bundleMetadata": "UNKNOWN (unreadable, invalid, oversized or changed during scan)", "responsibleAgent": "UNKNOWN (snapshot does not identify the actor)"]) { _, new in new }
                limitations.append("Application details could not be read consistently; no complete inventory or removal inference.")
                complete = false
            }
        } else {
            values["bundleMetadata"] = "UNKNOWN (.app entry is not a directory)"; complete = false
        }
        return (Observation(key: url.path, eventClass: .application, component: url.path, attributes: values, limitations: limitations, confidence: .moderate), complete)
    }

    /// lstat rejects a symlinked directory. ENOENT is scoped absence; other failures are unknown.
    private func directoryState(_ url: URL) throws -> String? {
        var value = stat()
        guard lstat(url.path, &value) == 0 else {
            if errno == ENOENT { return nil }
            throw TripWireError.message("Directory metadata unavailable")
        }
        guard value.st_mode & S_IFMT == S_IFDIR else { throw TripWireError.message("Directory is not a plain folder") }
        return "\(value.st_dev):\(value.st_ino):\(value.st_mtimespec.tv_sec):\(value.st_mtimespec.tv_nsec):\(value.st_ctimespec.tv_sec):\(value.st_ctimespec.tv_nsec)"
    }
}
