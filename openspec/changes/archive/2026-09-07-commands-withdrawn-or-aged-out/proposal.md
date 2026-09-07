# A queued command can be withdrawn, and ages out rather than being delivered late

## Why

Second half of issue #711. The bounded poll floor stops a host going permanently command-deaf, but it does nothing for the command already stranded, and there was no way to withdraw one: the operator surface exposed only `POST /api/commands` and `GET /api/commands/{id}`.

That is a safety gap rather than a missing convenience. `kill_process` addresses a PID, PIDs are reused, and the UI omits `pidversion` when the process node carries none. In the incident that produced this issue PID 70495 was a live interactive login shell, so clearing the wedge by restarting the agent would have delivered the stranded kill against whatever held that PID by then.

## What changes

- `POST /api/commands/{id}/cancel` withdraws a command no agent has taken. It requires the same authority as ISSUING that command type, not merely read access: preventing a response action is itself a response decision, and a reader who could cancel could disable incident response on a host they can only observe.
- Two new terminal states, `cancelled` and `expired`, both reachable only from `pending`. They are deliberately not folded into `failed`, which means an agent tried and could not. An operator auditing a host has to distinguish "nothing ran" from "something ran and went wrong".
- A command that has waited past the delivery window is aged out on the delivery read itself, so it is never handed to an agent late.

Ageing out happens where delivery happens rather than in a sweep loop. It needs no leader election, because the statement is idempotent and scoped to pending rows; it needs no cross-context wiring, because the leader-gated sweeps live in the detection context while command expiry belongs to response; and it cannot be outrun by a delivery, because the expiry write precedes the read that would answer one.

The known gap in that choice: a command queued for a host that never polls again is not aged out, because nothing reads its pending list. It is also never delivered, and an operator can now withdraw it, so the exposure is a stale row rather than a late kill.

## Impact

- Affected specs: `agent-control-channel`
- Affected code: `server/response/` (api types, service, mysql store, operator handler, migration)
- Migration `00002` widens the command status ENUM. The agent never sees either new state, because neither is deliverable, so there is no agent-side wire change.
- Still open on issue #711: fast detection of the split (a server-originated frame plus a receive deadline), and surfacing undeliverable commands on host health.
