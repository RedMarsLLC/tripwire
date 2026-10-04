import Foundation
import Darwin
import TripWireCore

/// Metadata from open vnode descriptors only. Never opens or reads the target files.
public struct AIFileAccessCollector: Collector {
    public static let id = "ai-open-files"
    public let descriptor = SensorDescriptor(id, "File-handle snapshots", source: "libproc process identities and open vnode descriptors",
        monitors: "Path metadata for regular files and directories held open by recognized same-user AI desktop apps and observed descendants; plus configured current-account boundaries; every 2 seconds while monitoring",
        limitations: [
            "Snapshots miss short-lived opens, closed files, memory-mapped files after close, and activity between checks. This is not a read/write event audit; loss is UNKNOWN.",
            "Read/write mode describes an open descriptor's capability, not proof that bytes were read or written. A descriptor can be inherited or passed from another process.",
            "App association uses bundle paths and sampled parent links, not signature attestation or proof of an AI action. Reparented, detached, other-user, protected and unrecognized agents may be missed.",
            "Recognized desktop apps: Codex, ChatGPT, Claude, Cursor, Ollama and LM Studio. Other processes are retained only for explicitly configured current-account boundaries.",
            "Only path/process/open-mode metadata is retained locally. No target file contents, arguments or environment values are read. Missing entries never establish deletion or no access."
        ])
    private let storeURL: URL?
    public init(storeURL: URL? = nil) { self.storeURL = storeURL }
    public func collect() async -> CollectorSnapshot {
        let apps = await AIAppResourceSampler.applications()
        let rules: [TripwireRule]
        do { rules = try storeURL.map { try EventStore(url: $0, access: .readOnly).tripwireRules() } ?? [] }
        catch { return CollectorSnapshot(descriptor: descriptor, state: .error, visibility: .unknown, detail: "Tripwire configuration could not be read; file scope is unknown.") }
        return Self.snapshot(rules: rules, apps: apps, inventory: Self.processes(), metadata: AIAppResourceSampler.metadata, files: Self.openFiles)
    }

    struct ProcessList { var values: [AIAppResourceSampler.ProcessMetadata]; var partial: Bool; var failed = false }
    struct OpenFile: Equatable {
        var path: String; var device: UInt32; var inode: UInt64; var flags: UInt32
        var isDirectory = false
        var mode: String {
            if flags & UInt32(O_EVTONLY) != 0 { return "Event-only (no read/write capability)" }
            switch flags & 3 {
            case 1: return "Read-capable"
            case 2: return "Write-capable"
            case 3: return "Read/write-capable"
            default: return "Unknown open mode"
            }
        }
    }
    struct FileList { var values: [OpenFile] = []; var partial = false; var denied = false }

    static func processes() -> ProcessList {
        var pids = [Int32](repeating: 0, count: 4096)
        let capacity = pids.count * MemoryLayout<Int32>.stride
        let bytes = proc_listpids(UInt32(PROC_UID_ONLY), getuid(), &pids, Int32(capacity))
        guard bytes > 0 else { return ProcessList(values: [], partial: true, failed: true) }
        var partial = bytes >= capacity
        let values = pids.prefix(min(pids.count, Int(bytes) / MemoryLayout<Int32>.stride)).filter { $0 > 0 }.compactMap { pid -> AIAppResourceSampler.ProcessMetadata? in
            guard let value = AIAppResourceSampler.metadata(pid) else { partial = true; return nil }
            return value
        }
        return ProcessList(values: values, partial: partial)
    }

    static func openFiles(_ pid: Int32) -> FileList {
        var result = FileList()
        var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: 4096)
        let capacity = fds.count * MemoryLayout<proc_fdinfo>.stride
        let bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, Int32(capacity))
        guard bytes > 0 else {
            // libproc does not distinguish an empty descriptor list from every failure.
            result.partial = true; result.denied = errno == EPERM || errno == EACCES; return result
        }
        result.partial = Int(bytes) >= capacity || Int(bytes) % MemoryLayout<proc_fdinfo>.stride != 0
        for fd in fds.prefix(min(fds.count, Int(bytes) / MemoryLayout<proc_fdinfo>.stride)) where fd.proc_fdtype == PROX_FDTYPE_VNODE {
            var info = vnode_fdinfowithpath()
            let read = proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDVNODEPATHINFO, &info, Int32(MemoryLayout<vnode_fdinfowithpath>.size))
            guard read == MemoryLayout<vnode_fdinfowithpath>.size else {
                result.partial = true; result.denied = result.denied || errno == EPERM || errno == EACCES; continue
            }
            // Directory handles matter for folder tripwires too. Never open the target.
            let kind = info.pvip.vip_vi.vi_stat.vst_mode & UInt16(S_IFMT)
            guard kind == UInt16(S_IFREG) || kind == UInt16(S_IFDIR) else { continue }
            let path = withUnsafeBytes(of: info.pvip.vip_path) { buffer -> String? in
                guard let end = buffer.firstIndex(of: 0), end > 0, end < buffer.count - 1 else { return nil }
                return String(bytes: buffer[..<end], encoding: .utf8)
            }
            guard let path, path.hasPrefix("/") else { result.partial = true; continue }
            result.values.append(OpenFile(path: path, device: info.pvip.vip_vi.vi_stat.vst_dev,
                                          inode: info.pvip.vip_vi.vi_stat.vst_ino, flags: info.pfi.fi_openflags, isDirectory: kind == UInt16(S_IFDIR)))
        }
        return result
    }

    static func snapshot(rules: [TripwireRule] = [], apps: [AIApplication], inventory: ProcessList,
                         metadata: (Int32) -> AIAppResourceSampler.ProcessMetadata?, files: (Int32) -> FileList,
                         home: String = FileManager.default.homeDirectoryForCurrentUser.path,
                         now: Date = Date(), maxFiles: Int = 2048, maxProcesses: Int = 128) -> CollectorSnapshot {
        let descriptor = Self().descriptor
        let accountRules = rules.filter { $0.enabled && $0.platform == .macOS && $0.effectiveScope == .currentUser }
        if apps.isEmpty && accountRules.isEmpty {
            return CollectorSnapshot(descriptor: descriptor, timestamp: now, complete: true, absenceReliable: false,
                detail: "No recognized AI desktop apps running at this check. Standalone CLI and unrecognized agents are outside scope; this does not establish no file access.")
        }
        guard !inventory.failed else {
            return CollectorSnapshot(descriptor: descriptor, timestamp: now, absenceReliable: false, state: .error, visibility: .unknown,
                detail: "Same-user process inventory could not be read; AI open-file visibility is unknown. Retry monitoring; no permission change is made automatically.")
        }
        let owners = AIAppResourceSampler.owners(apps: apps, processes: inventory.values)
        var partial = inventory.partial
        var samples: [Int32: FileList] = [:]
        var selected = inventory.values.filter { owners[$0.pid] != nil || !accountRules.isEmpty }.sorted { $0.pid < $1.pid }
        // Rotate bounded account-wide checks so high PIDs are not permanently
        // excluded by a large user's process inventory.
        if !accountRules.isEmpty && selected.count > maxProcesses && maxProcesses > 0 {
            let offset = (Int(ProcessInfo.processInfo.systemUptime / 2) * maxProcesses) % selected.count
            selected = Array(selected[offset...] + selected[..<offset])
        }
        var denied = 0, attempted = 0
        let deadline = ProcessInfo.processInfo.systemUptime + 1.5
        for process in selected.prefix(maxProcesses) {
            guard ProcessInfo.processInfo.systemUptime < deadline else { partial = true; break }
            let result = files(process.pid)
            samples[process.pid] = result; attempted += 1
            partial = partial || result.partial
            if result.denied { denied += 1 }
        }
        partial = partial || selected.count > attempted
        // Validate every ancestry node after the file sample, not just the final holder.
        let stable = inventory.values.filter { process in
            guard owners[process.pid] != nil || samples[process.pid] != nil else { return false }
            guard let after = metadata(process.pid), after.started == process.started,
                  after.path == process.path, after.parent == process.parent else { partial = true; return false }
            return true
        }
        let stableOwners = AIAppResourceSampler.owners(apps: apps, processes: stable)
        var observations: [String: Observation] = [:]
        for process in stable {
            guard let list = samples[process.pid] else { continue }
            let app = stableOwners[process.pid].flatMap { id in id == owners[process.pid] ? apps.first { $0.id == id } : nil }
            for file in list.values where app != nil || accountRules.contains(where: { TripwirePath.matches(file.path, rule: $0) }) {
                let key = Digest.sha256(Data("\(process.pid):\(process.started):\(process.path):\(file.device):\(file.inode):\(file.path):\(file.flags & (3 | UInt32(O_EVTONLY)))".utf8))
                if observations[key] == nil && observations.count >= maxFiles { partial = true; continue }
                var attrs = ["path": file.path, "collectorUID": String(getuid()), "operation": "Open descriptor sampled; actual read/write unknown",
                             "objectType": file.isDirectory ? "Directory" : "Regular file",
                             "openMode": file.mode, "executable": process.path, "pid": String(process.pid)]
                if let app {
                    attrs["associatedApp"] = app.name; attrs["associatedAppID"] = app.id
                    attrs["associationBasis"] = process.path.hasPrefix(app.bundlePath + "/") ? "Executable inside recognized app bundle" : "Observed parent chain to recognized app bundle"
                }
                if let parent = stable.first(where: { $0.pid == process.parent && $0.started <= process.started }) { attrs["parentExecutable"] = parent.path }
                if let reason = FileAccessReview.reason(path: file.path, home: home) { attrs["reviewReason"] = reason }
                let identity = ProcessIdentity(pid: process.pid, parentPID: process.parent, uid: getuid(), executablePath: process.path,
                    launchTime: Date(timeIntervalSince1970: Double(process.started) / 1_000_000))
                observations[key] = Observation(key: key, eventClass: .file, component: file.path, attributes: attrs,
                    process: identity, limitations: descriptor.limitations, confidence: .moderate)
            }
        }
        let emptyPartial = observations.isEmpty && partial
        return CollectorSnapshot(descriptor: descriptor, timestamp: now, observations: observations.values.sorted { $0.key < $1.key },
            complete: !partial, absenceReliable: false, state: emptyPartial ? .error : .degraded, visibility: emptyPartial ? .unknown : .limited,
            detail: "\(observations.count) distinct open-file records observed across \(attempted) checked processes within the configured scope. \(denied) process checks reported access denial. \(partial ? "Partial snapshot: some processes/descriptors changed, were unreadable or exceeded the sampling bounds. " : "")Checks target 2-second intervals; brief accesses and actual reads/writes are not audited. App association is not proof of an AI action.")
    }
}
