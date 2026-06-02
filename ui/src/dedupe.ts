// createDedupedRunner wraps an async task so that concurrent or rapid-fire
// invocations collapse to a single in-flight run instead of a storm. While a run is
// in progress, further calls are dropped; once it settles, the next call starts a
// fresh run.
//
// It backs the permission-set refetch triggered by a server 403 (see App.tsx): when
// several gated affordances on a page hit a 403 at once, the UI must issue at most one
// /api/session refetch rather than one per denial (the throttle requirement in the
// capability-gating spec). Errors from the task are swallowed here so a failed refetch
// simply ends the in-flight window and lets a later call retry; the caller logs as
// needed.
export function createDedupedRunner(task: () => Promise<void>): () => void {
  let inFlight = false;
  return () => {
    if (inFlight) return;
    inFlight = true;
    // Run the task inside Promise.resolve().then(...) so a SYNCHRONOUS throw (a task that
    // raises before returning its promise) is caught by the same .catch/.finally chain.
    // Without this, a sync throw would bypass finally and wedge inFlight=true forever,
    // permanently dropping every later call.
    void Promise.resolve()
      .then(() => task())
      .catch(() => undefined)
      .finally(() => {
        inFlight = false;
      });
  };
}
