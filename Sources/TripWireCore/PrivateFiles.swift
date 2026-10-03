import Foundation
#if os(Windows)
import CTripWirePlatform
#elseif canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// OS-specific store privacy checks. Never repairs permissions on an existing file.
enum PrivateFiles {
    static func size(_ path: String) throws -> UInt64? {
        #if os(Windows)
        var size: UInt64 = 0
        let result = tw_private_info(path, 0, 1, &size)
        guard result >= 0 else { throw TripWireError.message("Evidence file is unreadable, linked, or not private to this Windows account") }
        return result == 1 ? nil : size
        #else
        var info = stat()
        guard lstat(path, &info) == 0 else {
            if errno == ENOENT { return nil }
            throw TripWireError.message("Event-store metadata is unreadable")
        }
        guard info.st_size >= 0 else { throw TripWireError.message("Invalid evidence-file size") }
        return UInt64(info.st_size)
        #endif
    }
    static func validate(_ path: String, missingAllowed: Bool = false) throws {
        #if os(Windows)
        var ignored: UInt64 = 0
        guard tw_private_info(path, 0, missingAllowed ? 1 : 0, &ignored) >= 0 else {
            throw TripWireError.message("Evidence files require the current Windows account or token default owner, a private account/SYSTEM DACL and no reparse points or hard links")
        }
        #else
        var value = stat()
        if lstat(path, &value) != 0 {
            if missingAllowed && errno == ENOENT { return }
            throw TripWireError.message("Cannot verify event-store file metadata")
        }
        guard value.st_mode & S_IFMT == S_IFREG, value.st_uid == geteuid(), value.st_nlink == 1, value.st_mode & 0o077 == 0 else {
            throw TripWireError.message("Event-store files must be private regular files owned by this user (no symlinks, hard links or group/other access)")
        }
        #endif
    }
    static func prepareDirectory(_ url: URL) throws {
        #if os(Windows)
        guard tw_private_directory(url.path) == 0 else { throw TripWireError.message("Cannot create or verify a private Windows evidence directory; linked/network paths are unsupported") }
        #else
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        var parent = stat()
        guard lstat(url.path, &parent) == 0, parent.st_mode & S_IFMT == S_IFDIR, parent.st_uid == geteuid(), parent.st_mode & 0o022 == 0 else {
            throw TripWireError.message("Evidence directory must be owned by this user, not a symlink, and not group/other writable")
        }
        #endif
    }
    static func create(_ path: String) throws {
        #if os(Windows)
        guard tw_private_create(path) == 0 else { throw TripWireError.message("Could not securely create event store") }
        #else
        let fd = open(path, O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw TripWireError.message("Could not securely create event store") }
        close(fd)
        #endif
    }
    static func resolvedPath(_ url: URL) throws -> String {
        #if os(Windows)
        let path = url.path
        return path.hasPrefix("/") && path.dropFirst(2).hasPrefix(":") ? String(path.dropFirst()) : path
        #else
        guard let resolved = realpath(url.deletingLastPathComponent().path, nil) else { throw TripWireError.message("Cannot resolve evidence directory") }
        defer { free(resolved) }
        return String(cString: resolved) + "/" + url.lastPathComponent
        #endif
    }
}

public final class CollectorOwnerLock {
    #if os(Windows)
    private var handle: Int = -1
    #else
    private var fd: Int32 = -1
    #endif
    public init(url: URL) throws {
        let path = url.path + ".collector-lock"
        #if os(Windows)
        handle = tw_collector_lock(path)
        guard handle != -1 else { throw TripWireError.message("Collector lock is unavailable, insecure, or held by another owner") }
        #else
        let candidate = open(path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard candidate >= 0 else { throw TripWireError.message("Cannot open collector lock") }
        var info = stat()
        guard fstat(candidate, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == geteuid(), info.st_nlink == 1, info.st_mode & 0o077 == 0 else {
            close(candidate); throw TripWireError.message("Collector lock must be a private regular file owned by this user")
        }
        guard flock(candidate, LOCK_EX | LOCK_NB) == 0 else { close(candidate); throw TripWireError.message("Another collector owner is running. This interface can read the shared store.") }
        fd = candidate
        #endif
    }
    deinit {
        #if os(Windows)
        if handle != -1 { tw_collector_unlock(handle) }
        #else
        if fd >= 0 { flock(fd, LOCK_UN); close(fd) }
        #endif
    }
}
