# Design: durable, cross-transport command dedup

## The ledger

`agent/commandledger` is a single-table SQLite store (`command_outcomes(command_id PRIMARY KEY, status, result, updated_at)`) opened next to the event queue in the agent state directory, with the same pragmas (5s busy timeout, WAL, bounded WAL size) and a single writer connection. It exposes `Lookup`, `Mark` (upsert), and `Prune`. It is a per-agent store, not synced anywhere; command authority remains in MySQL.

## Write-ahead claim state machine

`commander.Executor.Execute` keys on the ledger:

1. `Lookup(id)`. If a terminal status (`completed` / `failed`) is recorded, re-ack and replay it; do not run the side effect. If `executing` is recorded (a prior attempt that claimed the command but never recorded a terminal outcome), do not run the side effect: terminalize as `failed` ("not retried") so the server stops re-delivering and an operator can re-issue against the current process.
2. Otherwise: ack. If the ack send fails, return without writing to the ledger, leaving the command eligible for re-dispatch.
3. `Mark(id, "executing")` BEFORE the side effect (write-ahead), so a crash between the side effect and recording its result is not re-run.
4. Run the side effect, `Mark(id, terminal, result)`, report the outcome.

A `Lookup` error does not wedge delivery: it is logged and execution proceeds (dedup degraded for that one command). A `Mark` error is logged but non-fatal.

### Why write-ahead, and why "executing" means a crashed prior attempt

There is no concurrent execution of the same command id within one process run: the poll is suspended while the control stream is connected, and each transport processes commands sequentially. So a `Lookup` that returns `executing` is always a claim left by a PRIOR process run that crashed between the write-ahead claim and recording the terminal outcome. Refusing to re-run it is the safety guard for `kill_process`: re-running could SIGKILL a process that has since reused the PID. The common restart case (the terminal outcome WAS recorded before the stop) is the replay branch, not this one.

## Sharing

Both `commander.New` (poll) and `controlclient.New` (push) take a `commander.Ledger`; `cmd/fleet-edr-agent` opens one `commandledger.Store` and passes it to both, so the at-most-once guarantee spans transports. The store is pruned on the agent's existing hourly prune loop. A nil ledger (tests) disables dedup; production always supplies one and fails to start if it cannot be opened, matching the event queue.
