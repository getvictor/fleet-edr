# Containment changes commit their audit entry

Issue #1070. Containing or releasing a host wrote its audit row after the change had committed, and a recorder failure was only logged. A failed audit write, or a replica stopping between the commit and the audit call, left a host cut off from the network with nothing recording who did it or why. The authorization chokepoint records the attempt, but that row does not say what changed, with what reason, or which command carried it. Detection config closed the same gap in #1022 and rule content in #886.

## What changes

- **An outbox in the response schema.** Migration 00006 adds `containment_audit_outbox`. A containment change writes its audit entry there in the transaction that records the state and queues its command (#1073), so the entry commits if and only if the change does. A drain turns entries into audit rows: the request delivers its own entry right after the change, and a sweep every minute delivers whatever a request could not. Delivery is at least once and never drops an entry.
- **The shared outbox serves a third context.** `auditoutbox` moves out of the rules context and takes its table as a constructor argument, so response adopts it with a table rather than a second copy of the encoding and the drain.
- **The entry carries the address the operator acted from.** The encoding gains `remote_addr`, which the containment row records and the rules rows do not. It is optional and the kind is unchanged: an entry a newer replica wrote and an older replica delivers loses the address rather than the row, where a new kind would strand every entry already written.
- **A refused change leaves no entry.** A reason that is missing or too long, a host that is not enrolled, a request for the state the host already has, and a change whose command cannot be queued all leave the outbox as they found it.

## Out of scope

- `command.issue`, which the operator command routes record after the insert commits and which has no transaction to join yet. It is the other half of #1070 and follows separately.
