# Pin kill_process to the target process generation

## Why

The `kill_process` response command is targeted by bare PID. The operator selects a process node in the UI (loaded seconds or minutes earlier) and the agent, on receipt, SIGKILLs that PID with only a `pid > 0` check. If the original process exited and the PID was reused (or re-exec'd) between tree load and command execution, the agent terminates an unrelated, possibly more privileged, process. PR #626 disabled the kill control once a process has exited, which removes the most common way to aim at a freed PID from the UI, but it does not close the window for a still-live process that gets re-PID'd before the command runs (issue #627).

Industry practice is to never act on a bare PID: bind the action to a reuse-proof process identity and verify it immediately before signaling (Linux `pidfd`, Windows `ProcessStartKey`, macOS `(pid, pidversion)`). macOS has no `pidfd`-style reuse-proof kill and no API to read a running PID's `pidversion` on demand (it is only ever carried on an Endpoint Security audit token), so the agent cannot look up a live generation at kill time. It can, however, accumulate `pid -> pidversion` from the exec/fork/exit event stream the extension already delivers, and verify against that.

## What changes

- **The kill_process payload carries an optional `pidversion`.** The UI includes the selected node's `pidversion` (already carried on events and the process graph) in the command payload. It is omitted for pre-migration / boot-snapshot nodes that have no `pidversion`, in which case the agent behaves exactly as today (pid-only kill). The server is unchanged: the command payload is opaque passthrough.
- **The agent maintains a live `pid -> pidversion` map.** A new per-agent, in-memory registry is fed from the ESF exec/fork/exit stream on the XPC receive path, before the lossy upload queue, so its fidelity tracks XPC delivery rather than upload backpressure. It is a per-replica cache, safe to lose (ADR-0010): an empty or stale map degrades to pid-only behavior.
- **The executor refuses a kill on a known generation mismatch.** When the command carries a `pidversion` and the registry tracks that PID at a different generation (PID reuse or re-exec), the executor reports the command failed with a clear reason and sends no signal. A match, or an untracked PID (never observed, since-exited, or lost across an agent restart), falls through to the kill. The check only ever strengthens the pid-only behavior: it never refuses a kill that would previously have succeeded.

### Not in this change

- An extension-owned generation map queried over a new correlated XPC request/reply. That is the maximally authoritative variant (closest to the ESF ground truth, robust to agent-side event drops) but is a larger, IPC-protocol change; it is a future hardening if the agent-side map is observed to drift.
- Any change to `kill(pid, SIGKILL)` itself or the reported-outcome contract for success / no-such-process / permission-denied.

## Acceptance

- A kill_process whose `pidversion` no longer matches the live generation of its target PID is refused with a structured failure and no signal is sent.
- A kill_process whose `pidversion` matches, or that carries no `pidversion`, or whose PID the agent does not track, is executed as today.
- The generation map is maintained from the event stream (exec/fork set the generation, exit clears it) and is never a source of event-delivery failure (a malformed event is ignored).
