import Foundation

/// DNSForwardCompletion resolves a single UDP DNS forward exactly once, and makes the deadline-vs-receive race atomic.
///
/// Two callbacks race for every forward: the bounded deadline (`DispatchWorkItem`) and the upstream `receiveMessage`
/// completion. A plain "check isFinished, then act" guard is a TOCTOU hole: the deadline can fire in the gap between the
/// receive path's check and its work, close the flow as a failure underneath an in-flight successful reply, and feed a
/// false failure into the health watchdog (potentially tripping a bypass). This type closes that race with a three-state
/// machine: the receive path must `claimResponse()` (pending -> responding) before it touches the flow; once claimed, the
/// deadline's `failIfPending()` is a no-op. Whichever side transitions out of `pending` first wins; the loser does nothing.
///
/// Pure Foundation (no NetworkExtension import) so the transition semantics are unit-testable.
final class DNSForwardCompletion {
    private enum State {
        case pending     // no outcome yet
        case responding  // the receive path has claimed the forward and is writing the reply back
        case done        // resolved; onResolve has run
    }

    private let lock = NSLock()
    private var state: State = .pending
    private let onResolve: (Bool) -> Void

    /// onResolve runs exactly once, on the winning path, with the final outcome (true == upstream answered and the reply
    /// was written back). It carries the cleanup: record the health sample, tear down the connection, and on failure close
    /// the flow.
    init(_ onResolve: @escaping (Bool) -> Void) { self.onResolve = onResolve }

    /// Receive path: atomically claim the forward so the racing deadline becomes a no-op. Returns true if claimed (the
    /// caller then writes the reply and calls `resolveResponse`), false if the deadline (or another terminal path) already
    /// resolved it first, in which case the caller must not touch the flow.
    func claimResponse() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard state == .pending else { return false }
        state = .responding
        return true
    }

    /// Deadline / connection-failure / send-error path: resolve as a failure only if still pending. If the receive path has
    /// already claimed (`responding`) or the forward is `done`, this is a no-op, so a near-deadline success is never
    /// reclassified as a failure and the flow is never closed out from under the receive path. Returns true only when this
    /// call actually won the race (pending -> done), so the deadline caller can log "timed out" only when it genuinely
    /// timed out rather than on every near-deadline success (a misleading operator signal otherwise).
    @discardableResult
    func failIfPending() -> Bool {
        lock.lock()
        guard state == .pending else {
            lock.unlock()
            return false
        }
        state = .done
        lock.unlock()
        onResolve(false)
        return true
    }

    /// Receive path: finalize a forward this caller already claimed via `claimResponse`, once the reply has (or has not)
    /// been written back. A no-op unless the forward is in the `responding` state this caller put it in.
    func resolveResponse(ok: Bool) {
        lock.lock()
        guard state == .responding else {
            lock.unlock()
            return
        }
        state = .done
        lock.unlock()
        onResolve(ok)
    }
}
