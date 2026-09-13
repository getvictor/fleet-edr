# Detection-config changes commit their audit entry

Issue #1022. Every detection-config change wrote its audit row after its transaction committed, and logged rather than returned a failure: creating or deleting an exclusion, changing a rule setting, and replacing the watched-path set. A failed audit write, or a replica stopping between the commit and the audit call, left a change to what the fleet detects or collects with nothing recording who made it or why. Rule content closed the same gap in #886 with an outbox.

## What changes

- **An outbox in the rules schema.** Migration 00008 adds `detection_config_audit_outbox`. Each change writes its audit entry there in the transaction that makes it, so the entry commits if and only if the change does. A drain turns entries into audit rows: the request delivers its own entry right after the change, and a sweep every minute delivers whatever a request could not. Delivery is at least once and never drops an entry, the same guarantee rule content has.
- **One drain for both outboxes.** The rule-content drain and its encoding move to a shared `auditoutbox` package, unchanged in behavior. Rule content adapts its own outbox to it, and detection config reads its new table through it.
- **The watched-path row keeps its push counts.** A replacement's audit row reports how many hosts the set was queued for, which is known only after the transaction commits. Its entry is written held and released by the writer once it adds the counts. If the writer stops first, the hold lapses after five minutes and the entry is delivered without the counts rather than not at all.
- **The row keeps the change's trace.** An entry carries the trace of the request that made the change, because the drain that delivers it may run in another request or on the sweep.
- **A refused change leaves no entry**: validation failures, a missing exclusion, and an invalid watched-path set roll back with the change.
- The watched-paths-server delta's statement that a failed audit write is logged and does not undo the change is replaced by the new requirement.

## Out of scope

- Application control's audit rows, which follow the same post-commit pattern and are not part of #1022.
