import Darwin
import Foundation

/// proc_pidpath wants room for the resolved path. macOS's PROC_PIDPATHINFO_MAXSIZE
/// is 4 * MAXPATHLEN; size the buffer the same way so any kernel-side bump is
/// covered without us editing both ends.
private let processPathBufferMultiplier = 4

/// Returns the executable path for a given PID using proc_pidpath, or "unknown" on failure.
func processPath(for pid: pid_t) -> String {
    guard pid > 0 else { return "unknown" }
    let bufferSize = processPathBufferMultiplier * Int(MAXPATHLEN)
    let buffer = UnsafeMutablePointer<CChar>.allocate(capacity: bufferSize)
    defer { buffer.deallocate() }
    let result = proc_pidpath(pid, buffer, UInt32(bufferSize))
    guard result > 0 else { return "unknown" }
    return String(cString: buffer)
}

/// Extracts PID, effective UID, and the kernel PID generation (pidversion) from an audit token data blob. pidversion is nil
/// only when the token is absent: it lets the server correlate a flow to the exact process generation by identity rather than
/// a fork-to-exit time window, immune to PID reuse (issue #403). pid/pidversion come from the same token, so the caller picks
/// which token to pass (the socket filter prefers sourceProcessAuditToken, the actual flow-creating process; the DNS proxy
/// only has sourceAppAuditToken).
func extractProcessInfo(from auditToken: Data?) -> (pid: pid_t, uid: uid_t, pidversion: UInt32?) {
    var pid: pid_t = -1
    var uid: uid_t = 0
    var pidversion: UInt32?
    guard let token = auditToken else { return (pid, uid, pidversion) }
    token.withUnsafeBytes { buf in
        guard buf.count >= MemoryLayout<audit_token_t>.size else { return }
        // swiftlint:disable:next force_unwrapping
        let ptr = buf.baseAddress!.assumingMemoryBound(to: audit_token_t.self)
        pid = audit_token_to_pid(ptr.pointee)
        uid = audit_token_to_euid(ptr.pointee)
        // pidversion (kernel PID generation) is non-negative in practice; bitPattern avoids a trap on a theoretical negative.
        pidversion = UInt32(bitPattern: audit_token_to_pidversion(ptr.pointee))
    }
    return (pid, uid, pidversion)
}
