import Darwin
import Foundation
import Security

/// SnapshotSigning recovers the code signature of a process that was already running when the extension started, so a startup
/// snapshot exec carries the same `code_signing` a live exec does.
///
/// Without it the server holds no signature for any process that predates the extension (everything started at boot, and every
/// process alive across an agent upgrade) until that process exits. Every judgement made on the signature then fails: a rule's
/// built-in skip of Apple's indexers, and an operator's `team_id` or `signing_id` exclusion, so the process is reported instead.
/// Spotlight's `mds`, which runs for as long as the Mac is up, was reported as browser credential theft for exactly this reason.
///
/// The signature is the RUNNING code's, read through its guest code object, not the file on disk: the binary may have been
/// replaced since the process started. Only signing information is read; nothing is validated, so no network is touched.
enum SnapshotSigning {
    /// platformBinaryFlag is CS_PLATFORM_BINARY from the kernel's code-signing flags, the bit ES reports as `is_platform_binary`.
    static let platformBinaryFlag: UInt32 = 0x0400_0000
    /// pidPathBufferPaths is how many MAXPATHLEN buffers PROC_PIDPATHINFO_MAXSIZE, the size proc_pidpath fills, spans. The C macro
    /// does not import into Swift.
    private static let pidPathBufferPaths = 4
    private static let pidPathBufferSize = pidPathBufferPaths * Int(MAXPATHLEN)

    /// codeSigning maps the dictionary SecCodeCopySigningInformation returns to the shape an exec event carries, or nil when the
    /// code carries no identifier, which is an unsigned process: it has no signature to report, the same as a live exec of one.
    static func codeSigning(from info: [String: Any]) -> CodeSigning? {
        guard let identifier = info[kSecCodeInfoIdentifier as String] as? String, !identifier.isEmpty else {
            return nil
        }
        let flags = (info[kSecCodeInfoStatus as String] as? NSNumber)?.uint32Value ?? 0
        return CodeSigning(
            teamID: info[kSecCodeInfoTeamIdentifier as String] as? String ?? "",
            signingID: identifier,
            flags: flags,
            isPlatformBinary: flags & platformBinaryFlag != 0
        )
    }

    /// live returns the running process's signature, or nil when it cannot be read or the pid no longer runs what was listed. Two
    /// things can change under the read. The pid can be reused by a new process, which the start time catches; and the listed
    /// process can exec another program, which keeps its start time but not its path. A signature is attributed only when both
    /// still match, so it describes the program the snapshot reports at `path`. Both are checked before the read and again after it,
    /// so the signature is taken only while the identity held across the whole read.
    static func live(pid: pid_t, startTime: timeval, path: String) -> CodeSigning? {
        guard stillListed(pid: pid, startTime: startTime, path: path) else {
            return nil
        }
        var guest: SecCode?
        let attributes = [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &guest) == errSecSuccess, let code = guest else {
            return nil
        }
        // The guest code, not its static code: only the running code reports the kernel's status flags, the value ES carries as
        // `codesigning_flags`. SecCodeCopySigningInformation takes a SecCode in place of a SecStaticCode, as its header says; the
        // Swift binding types the parameter as the static class, hence the cast.
        var info: CFDictionary?
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSDynamicInformation)
        let running = unsafeBitCast(code, to: SecStaticCode.self)
        guard SecCodeCopySigningInformation(running, flags, &info) == errSecSuccess, let dict = info as? [String: Any] else {
            return nil
        }
        guard stillListed(pid: pid, startTime: startTime, path: path) else {
            return nil
        }
        return codeSigning(from: dict)
    }

    /// stillListed reports whether the pid still runs the process the snapshot listed: same start time, same program path.
    private static func stillListed(pid: pid_t, startTime: timeval, path: String) -> Bool {
        sameStartTime(startTime, processStartTime(pid: pid)) && !path.isEmpty && processPath(pid: pid) == path
    }

    /// sameStartTime reports whether the process now holding the pid started when the listed one did.
    static func sameStartTime(_ listed: timeval, _ current: timeval?) -> Bool {
        guard let current else {
            return false
        }
        return listed.tv_sec == current.tv_sec && listed.tv_usec == current.tv_usec
    }

    /// processPath is the executable path of a running process, or nil when it cannot be read. The snapshot uses it for the path it
    /// reports as well as for this recheck, so both read it the same way.
    static func processPath(pid: pid_t) -> String? {
        var buf = [CChar](repeating: 0, count: pidPathBufferSize)
        guard proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 else {
            return nil
        }
        return String(cString: buf)
    }

    private static func processStartTime(pid: pid_t) -> timeval? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else {
            return nil
        }
        return timeval(tv_sec: Int(info.pbi_start_tvsec), tv_usec: Int32(info.pbi_start_tvusec))
    }
}
