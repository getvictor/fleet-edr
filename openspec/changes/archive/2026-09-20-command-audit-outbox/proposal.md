# Command issuance and withdrawal commit their audit entry

Issue #1070, second half, and issue #1085. Issuing a command through `POST /api/commands` and withdrawing one through `POST /api/commands/{id}/cancel` each wrote their audit row after the change had committed, and a recorder failure was only logged. A failed audit write, or a replica stopping between the two, left a `kill_process` sent to a host with nothing recording who sent it. Containment closed the same gap for itself in #1087, detection config in #1022, and rule content in #886.

Both routes also shared one audit helper that named `command.issue`, so a withdrawal recorded a row saying the command had been issued (#1085). The two rows are otherwise identical, naming the same host, command type and command id, so nothing in the trail told them apart and a count of issued response actions over-reported by every withdrawal.

## What changes

- **Both actions commit their entry with the change.** The command row and the audit entry recording it are written in one transaction, into the `response_audit_outbox` that containment already uses, so the context's audit rows keep a single order. The entry is built inside the transaction because it carries the command id, which is only known once the row is written. A refused action leaves no entry.
- **The delivery is the one the context already has.** The request asks the context's existing sweep for its entry after the commit, and that sweep delivers it, so this adds no second drain and no second table.
- **A withdrawal is audited as `command.cancel`.** The action becomes the caller's rather than a constant shared by both routes.

## Out of scope

- The agent-driven status updates (`acked`, `completed`, `failed`), which are the host reporting what it did rather than an operator acting, and which the command row itself records.
