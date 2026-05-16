import Darwin
import Foundation
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "ProcessSnapshot")

/// Hard cap on enumerated PIDs. Normal macOS process tables stay well under a few thousand
/// and the kernel hard maximum is ~kern.maxproc (usually 2048-3072). Pinning a generous
/// upper bound here defends against a runaway sysctl reply or a future kernel that returns
/// a wildly larger list, without changing real-world behavior.
private let maxEnumeratedPIDs = 16_384

/// proc_pidpath wants room for the resolved path. macOS's PROC_PIDPATHINFO_MAXSIZE
/// is 4 * MAXPATHLEN; size the buffer the same way so any kernel-side bump is covered
/// without us editing both ends. Matches the networkextension/ProcessInfo helper.
private let pathBufferMultiplier = 4

/// Re-probe loop cap when the kinfo_proc buffer needs to grow between the size probe
/// and the fill call (the process table grew due to forks in that window). Three
/// attempts is plenty in practice; an unbounded loop would risk an infinite spin on
/// pathological growth.
private let kinfoProbeMaxAttempts = 3

/// Slack added to the size returned by the kinfo_proc size probe. The probe + fill
/// pair is not atomic; new forks between them grow the table. Pad by N additional
/// kinfo_proc slots so one or two new forks don't force a re-probe.
private let kinfoSizeSlackEntries = 64

/// ProcessSnapshotEnumerator walks the live process table at extension startup and emits a
/// synthetic exec event per running PID. The events carry snapshot=true so the server-side
/// detection engine drops them from rule evaluation (filter.go, issue #11) but the graph
/// builder still materialises them into the processes table — the analyst sees Safari,
/// Slack, Finder, etc. in the tree even though ESF couldn't observe their original
/// fork/exec because they pre-dated subscribe.
///
/// Why sysctl KERN_PROC_ALL and not proc_listallpids:
///
/// On macOS 26, proc_listallpids is heavily filtered even for root callers — empirically
/// returns ~12% of the real process table on a SIP-disabled VM (56 of 473 live PIDs in
/// QA). The KERN_PROC sysctl is what `ps` uses and surfaces every process the caller has
/// permission to see, which for a root-level ES extension is everything. The sysctl also
/// returns kinfo_proc structs directly, so we get pid/ppid/uid/gid in one call instead of
/// a second sysctl per PID.
///
/// Why run AFTER es_subscribe finishes (caller responsibility):
///
/// If we enumerated first and subscribed second, processes that exec'd in the window
/// between enumeration and subscribe would be invisible (the snapshot captured a stale
/// PID; the live stream missed the new exec). Running after subscribe means the small
/// race window goes the other way — a snapshot may include a process whose exit event
/// was just delivered live. The graph builder's UpdateProcessExit + insertExecWithoutFork
/// flow handles that duplicate gracefully.
enum ProcessSnapshotEnumerator {
    /// Run the baseline pass. `emit` is invoked once per live PID with a fully-formed
    /// ExecPayload (snapshot=true). The function blocks on the caller's thread; main.swift
    /// schedules it onto a background dispatch queue so ESF callback delivery is not held
    /// up by the per-PID proc_pidpath call.
    static func run(emit: (ExecPayload) -> Void) {
        let processes = listAllProcesses()
        logger.info("ESF startup snapshot: enumerating \(processes.count, privacy: .public) live processes")

        var emitted = 0
        for info in processes where info.pid > 0 {
            let path = resolvePath(pid: info.pid)
            let payload = ExecPayload(
                pid: info.pid,
                ppid: info.ppid,
                path: path,
                args: [],
                cwd: "",
                uid: info.uid,
                gid: info.gid,
                codeSigning: nil,
                sha256: nil,
                snapshot: true
            )
            emit(payload)
            emitted += 1
        }
        logger.info("ESF startup snapshot: emitted \(emitted, privacy: .public) baseline exec events")
    }

    /// listAllProcesses runs the standard sysctl(CTL_KERN, KERN_PROC, KERN_PROC_ALL) size-
    /// probe-then-fill dance, retrying the fill when the table grew in between (ENOMEM).
    /// Returns the live process table as a typed Swift array; an empty result on a
    /// hard failure is logged at warning and falls through silently — the caller already
    /// no-ops on an empty list and the missing snapshot for one boot is preferable to a
    /// crash.
    private static func listAllProcesses() -> [ProcIdentity] {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL]
        for attempt in 0..<kinfoProbeMaxAttempts {
            var size = 0
            let probeRC = mib.withUnsafeMutableBufferPointer { ptr in
                sysctl(ptr.baseAddress, UInt32(ptr.count), nil, &size, nil, 0)
            }
            guard probeRC == 0, size > 0 else {
                logger.warning("kinfo_proc size probe failed: errno=\(errno, privacy: .public) attempt=\(attempt, privacy: .public)")
                return []
            }
            let stride = MemoryLayout<kinfo_proc>.stride
            let probeCount = size / stride
            // Don't cap the BUFFER size — sysctl returns ENOMEM if the buffer is too
            // small, and retrying with the same kernel-reported size loses every
            // process on a host with > maxEnumeratedPIDs live. Allocate for what the
            // kernel reports + slack, then cap the RESULT count below.
            let capacity = probeCount + kinfoSizeSlackEntries
            var buffer = [kinfo_proc](repeating: kinfo_proc(), count: capacity)
            var filledSize = capacity * stride
            let fillRC = mib.withUnsafeMutableBufferPointer { mibPtr in
                buffer.withUnsafeMutableBufferPointer { bufPtr -> Int32 in
                    sysctl(mibPtr.baseAddress, UInt32(mibPtr.count), bufPtr.baseAddress, &filledSize, nil, 0)
                }
            }
            if fillRC == 0 {
                let count = min(maxEnumeratedPIDs, filledSize / stride)
                return buffer.prefix(count).map(ProcIdentity.init)
            }
            // ENOMEM means the table grew past our buffer between probe + fill. Retry —
            // the next probe sees the new size.
            if errno != ENOMEM {
                logger.warning("kinfo_proc fill failed: errno=\(errno, privacy: .public) attempt=\(attempt, privacy: .public)")
                return []
            }
        }
        logger.warning("kinfo_proc fill exceeded retry budget; skipping snapshot for this boot")
        return []
    }

    private static func resolvePath(pid: pid_t) -> String {
        let size = pathBufferMultiplier * Int(MAXPATHLEN)
        var buf = [CChar](repeating: 0, count: size)
        let result = proc_pidpath(pid, &buf, UInt32(size))
        guard result > 0 else { return "" }
        return String(cString: buf)
    }
}

/// ProcIdentity captures the per-PID identifiers we surface from a kinfo_proc into the
/// ExecPayload. A named struct rather than a tuple because SwiftLint's large_tuple cap is
/// 2 — and named fields document the call sites.
private struct ProcIdentity {
    let pid: pid_t
    let ppid: pid_t
    let uid: uid_t
    let gid: gid_t

    init(_ kp: kinfo_proc) {
        self.pid = kp.kp_proc.p_pid
        self.ppid = kp.kp_eproc.e_ppid
        self.uid = kp.kp_eproc.e_ucred.cr_uid
        self.gid = kp.kp_eproc.e_ucred.cr_ngroups > 0 ? kp.kp_eproc.e_ucred.cr_groups.0 : 0
    }
}
