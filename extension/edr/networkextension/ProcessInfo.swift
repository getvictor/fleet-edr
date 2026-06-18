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

/// Process identity extracted from a flow's audit token. A named value type rather than a tuple so it stays under SwiftLint's
/// large_tuple cap (>2 members) and reads clearly at the call sites.
struct ProcessIdentity {
    let pid: pid_t
    let uid: uid_t
    /// Kernel PID generation (audit_token_to_pidversion); nil only when the token was absent (issue #403).
    let pidversion: UInt32?
}

/// Extracts PID, effective UID, and the kernel PID generation (pidversion) from an audit token data blob. pidversion is nil
/// only when the token is absent: it lets the server correlate a flow to the exact process generation by identity rather than
/// a fork-to-exit time window, immune to PID reuse (issue #403). pid/pidversion come from the same token, so the caller picks
/// which token to pass (the socket filter prefers sourceProcessAuditToken, the actual flow-creating process; the DNS proxy
/// only has sourceAppAuditToken).
func extractProcessInfo(from auditToken: Data?) -> ProcessIdentity {
    guard let auditToken, auditToken.count >= MemoryLayout<audit_token_t>.size else {
        return ProcessIdentity(pid: -1, uid: 0, pidversion: nil)
    }
    // loadUnaligned copies the bytes into a value: Data's storage is not guaranteed aligned for audit_token_t, so an aligned
    // load (or assumingMemoryBound) would be undefined behaviour on strict-alignment archs. It also drops the baseAddress
    // force-unwrap, so no swiftlint bypass is needed (Gemini + Copilot review).
    let token = auditToken.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) }
    return ProcessIdentity(
        pid: audit_token_to_pid(token),
        uid: audit_token_to_euid(token),
        // pidversion (kernel PID generation) is non-negative in practice; bitPattern avoids a trap on a theoretical negative.
        pidversion: UInt32(bitPattern: audit_token_to_pidversion(token))
    )
}
