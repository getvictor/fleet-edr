import Darwin
import Foundation

/// Returns the executable path for a given PID using proc_pidpath, or "unknown" on failure.
func processPath(for pid: pid_t) -> String {
    guard pid > 0 else { return "unknown" }
    let bufferSize = 4 * Int(MAXPATHLEN)
    let buffer = UnsafeMutablePointer<CChar>.allocate(capacity: bufferSize)
    defer { buffer.deallocate() }
    let result = proc_pidpath(pid, buffer, UInt32(bufferSize))
    guard result > 0 else { return "unknown" }
    return String(cString: buffer)
}

/// Extracts PID and UID from an audit token data blob.
func extractProcessInfo(from auditToken: Data?) -> (pid: pid_t, uid: uid_t) {
    var pid: pid_t = -1
    var uid: uid_t = 0
    guard let token = auditToken else { return (pid, uid) }
    token.withUnsafeBytes { buf in
        guard buf.count >= MemoryLayout<audit_token_t>.size else { return }
        // swiftlint:disable:next force_unwrapping
        let ptr = buf.baseAddress!.assumingMemoryBound(to: audit_token_t.self)
        pid = audit_token_to_pid(ptr.pointee)
        uid = audit_token_to_euid(ptr.pointee)
    }
    return (pid, uid)
}
