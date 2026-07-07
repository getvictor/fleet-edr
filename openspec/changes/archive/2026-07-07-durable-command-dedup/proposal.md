# Durable, cross-transport command dedup

## Why

The push control channel and the poll path each construct their own command executor, and the only dedup state was an in-memory cache local to the control client. So the "side effect runs at most once" guarantee (the `agent-control-channel` delivery requirement) held only within the push transport, within a single process run. Two windows escaped it (issue #558):

- **Cross-transport.** A `kill_process` executed over the control connection, whose ack/outcome did not reach the server before the stream dropped, stays pending. The poll path resumes and re-executes it with a fresh executor that has no memory of the push-path cache, flipping a succeeded kill to `failed`.
- **Restart + PID reuse.** The in-memory cache is lost on restart, so a still-pending command re-delivered after a restart re-executes. Because `kill_process` carries only a bare PID, and PIDs are reused, a post-restart re-execution could signal an unrelated process.

This change makes the at-most-once guarantee actually hold, durably and across both transports.

## What changes

- A small persistent SQLite ledger (`agent/commandledger`), keyed by the server command id, records each command as `executing` (a write-ahead claim taken before the side effect) and then `completed` / `failed` (the terminal outcome).
- The shared `commander.Executor` consults the ledger: a command with a recorded terminal outcome is replayed (re-acked and re-reported) without re-running the side effect; a command with only a write-ahead claim (a prior attempt that crashed mid-execution) is terminalized as failed rather than re-run, so a re-delivery never re-signals a possibly-reused PID. Both the poll path and the control client share one ledger.
- The control client's in-memory outcome cache is removed (the ledger subsumes it).

## Affected specs

- `agent-command-executor`: ADDED requirement that command execution is deduplicated durably across transports and restarts, with a write-ahead claim before the side effect. This realizes, end to end, the existing `agent-control-channel` "side effect at most once / record each outcome" requirement, which previously held only in memory within one transport.
