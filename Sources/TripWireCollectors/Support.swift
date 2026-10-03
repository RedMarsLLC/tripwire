import Foundation
import Security
import TripWireCore

public struct CommandResult {
    public var output: Data
    public var error: Data
    public var status: Int32
    public var truncated: Bool
    public var timedOut: Bool
    public var text: String { String(decoding: output, as: UTF8.self) }
    public var successful: Bool { status == 0 && !truncated && !timedOut }
}
private final class Capture {
    private let lock = NSLock()
    private var data = Data()
    private var exceeded = false
    func append(_ bytes: Data) { lock.lock(); defer { lock.unlock() }; let remaining = max(0, 8 * 1024 * 1024 - data.count); data.append(bytes.prefix(remaining)); if bytes.count > remaining { exceeded = true } }
    func value() -> (Data, Bool) { lock.lock(); defer { lock.unlock() }; return (data, exceeded) }
}
public enum ReadCommand {
    /// No shell, interpolated command text, inherited PATH, stdin, or shell expansion.
    public static func run(_ path: String, _ arguments: [String], timeout: TimeInterval = 12) -> CommandResult {
        let process = Process(); process.executableURL = URL(fileURLWithPath: path); process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "LANG": "C", "HOME": FileManager.default.homeDirectoryForCurrentUser.path]
        process.standardInput = FileHandle.nullDevice
        let out = Pipe(), err = Pipe(); process.standardOutput = out; process.standardError = err
        let a = Capture(), b = Capture(), group = DispatchGroup()
        do { try process.run() } catch { return CommandResult(output: Data(), error: Data("Could not launch source".utf8), status: -1, truncated: false, timedOut: false) }
        for (pipe, capture) in [(out, a), (err, b)] {
            group.enter(); DispatchQueue.global(qos: .utility).async {
                while true { let d = pipe.fileHandleForReading.availableData; if d.isEmpty { break }; capture.append(d) }
                group.leave()
            }
        }
        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.025) }
        let timedOut = process.isRunning
        if timedOut { process.terminate() }
        // Only terminate this tool's own bounded diagnostic child, never a monitored process.
        let grace = Date().addingTimeInterval(1)
        while process.isRunning && Date() < grace { Thread.sleep(forTimeInterval: 0.025) }
        if process.isRunning { kill(process.processIdentifier, SIGKILL) }
        process.waitUntilExit(); group.wait()
        let av = a.value(), bv = b.value()
        return CommandResult(output: av.0, error: bv.0, status: process.terminationStatus, truncated: av.1 || bv.1, timedOut: timedOut)
    }
}
public enum Signature {
    public static func identity(_ path: String) -> ProcessIdentity {
        var result = ProcessIdentity(executablePath: path)
        var code: SecStaticCode?
        let status = SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, SecCSFlags(), &code)
        guard status == errSecSuccess, let code else { result.signatureStatus = "UNKNOWN (\(status))"; return result }
        var info: CFDictionary?
        let copied = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
        if copied == errSecCSUnsigned { result.signatureStatus = "UNSIGNED"; return result }
        guard copied == errSecSuccess, let dict = info as? [String: Any] else { result.signatureStatus = "UNKNOWN (\(copied))"; return result }
        result.bundleID = dict[kSecCodeInfoIdentifier as String] as? String
        result.teamID = dict[kSecCodeInfoTeamIdentifier as String] as? String
        if let certificates = dict[kSecCodeInfoCertificates as String] as? [SecCertificate], let certificate = certificates.first { result.signingIdentity = SecCertificateCopySubjectSummary(certificate) as String? }
        // Metadata extraction is not a full signature validation or a verdict about behavior.
        result.signatureStatus = "SIGNING METADATA PRESENT (validity not checked)"
        return result
    }
}
public enum SafeFile {
    public static func requirePrivateDirectory(_ url: URL) throws {
        var attrs = stat()
        guard lstat(url.path, &attrs) == 0, attrs.st_mode & S_IFMT == S_IFDIR, attrs.st_uid == geteuid(), attrs.st_mode & 0o077 == 0 else {
            throw TripWireError.message("Canary directory must be private, owned by this user and not a symlink")
        }
    }

    public static func isMissing(_ error: Error) -> Bool {
        let e = error as NSError
        if e.domain == NSCocoaErrorDomain && [NSFileReadNoSuchFileError, NSFileNoSuchFileError].contains(e.code) { return true }
        return e.domain == NSPOSIXErrorDomain && e.code == Int(ENOENT)
    }

    public struct Inspection {
        public var metadata: [String: String]
        // Ephemeral bytes used only to hash/parse explicitly scoped metadata files; never stored.
        public var data: Data?
    }
    public static func inspect(_ url: URL, hash: Bool) throws -> Inspection {
        let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
        var values = ["path": url.path, "ownerUID": "\(attrs[.ownerAccountID] ?? "UNKNOWN")", "groupGID": "\(attrs[.groupOwnerAccountID] ?? "UNKNOWN")", "mode": String(format: "%04o", (attrs[.posixPermissions] as? NSNumber)?.intValue ?? 0), "type": (attrs[.type] as? FileAttributeType)?.rawValue ?? "UNKNOWN"]
        values["sizeBytes"] = (attrs[.size] as? NSNumber)?.stringValue ?? "UNKNOWN"
        values["modifiedAt"] = (attrs[.modificationDate] as? Date).map { String($0.timeIntervalSince1970) } ?? "UNKNOWN"
        if attrs[.type] as? FileAttributeType == .typeSymbolicLink {
            values["symlinkTarget"] = try FileManager.default.destinationOfSymbolicLink(atPath: url.path)
            values["hash"] = "NOT OBSERVABLE (symlink not followed)"
            return Inspection(metadata: values, data: nil)
        }
        guard hash, attrs[.type] as? FileAttributeType == .typeRegular else { return Inspection(metadata: values, data: nil) }
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw TripWireError.message("Metadata file unreadable or changed during scan") }
        defer { close(fd) }
        var before = stat(), after = stat()
        guard fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFREG else { throw TripWireError.message("Metadata file no longer regular") }
        values["sizeBytes"] = String(before.st_size); values["modifiedAt"] = String(Double(before.st_mtimespec.tv_sec) + Double(before.st_mtimespec.tv_nsec) / 1_000_000_000)
        values["ownerUID"] = String(before.st_uid); values["groupGID"] = String(before.st_gid); values["mode"] = String(format: "%04o", before.st_mode & 0o7777)
        guard before.st_size <= 2 * 1024 * 1024 else {
            values["hash"] = "NOT OBSERVABLE (2 MiB metadata-file limit)"
            return Inspection(metadata: values, data: nil)
        }
        var data = Data(), buffer = [UInt8](repeating: 0, count: 32768)
        while true {
            let count = Darwin.read(fd, &buffer, buffer.count)
            guard count >= 0 else { throw TripWireError.message("Metadata read failed") }
            if count == 0 { break }
            guard data.count + count <= 2 * 1024 * 1024 else { throw TripWireError.message("Metadata file grew beyond limit") }
            data.append(contentsOf: buffer.prefix(count))
        }
        guard fstat(fd, &after) == 0, before.st_size == after.st_size, before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec, before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec, before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec, before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else { throw TripWireError.message("Metadata changed during read; observation discarded") }
        values["sha256"] = Digest.sha256(data)
        return Inspection(metadata: values, data: data)
    }
    public static func metadata(_ url: URL, hash: Bool) throws -> [String: String] { try inspect(url, hash: hash).metadata }
}
