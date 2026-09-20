# Concurrent rule changes to one policy serialize instead of deadlocking

Issue #1057. Application-control rule mutations took row locks in two different orders, so concurrent writes to the same policy could deadlock. MySQL picks a victim, aborts it with error 1213, and the caller gets a 500.

Every rule mutation touches two rows: the rule, and the policy whose version bump is what makes the change visible to hosts. The single-rule paths wrote or locked the rule first and bumped the policy second; bulk upsert locked the policy first and then touched rules. Two writers approaching from opposite ends each hold what the other needs.

Creates had a second shape that needed no bulk upsert at all: the INSERT takes a SHARED lock on the parent policy row through the foreign key, and the version bump then needs an EXCLUSIVE one, so two concurrent creates in one policy deadlock on the upgrade.

Both shapes reproduce against a real MySQL. Eight concurrent creates over four rounds produced 21 deadlocks, and concurrent single-rule updates against a bulk upsert produced 7, before this change and none after.

## What changes

- **Every rule mutation locks the policy row first**, which is what bulk upsert already did. `lockPolicyForBulkUpsert` becomes `lockPolicy`, because the ordering is the whole store's rule rather than one method's detail.
- **Create, update and delete take it before touching the rule.** Update and delete learn which policy from the rule, so they read its `policy_id` without a lock first. That read cannot go stale: no update sets `policy_id`, so a rule never moves policy. A rule deleted in between is reported missing by the locked read that follows, exactly as before.
- **A create against a missing policy is answered by the lock** rather than by interpreting a foreign-key violation afterwards.

## Why ordering rather than retry

`sqlhelpers.WithDeadlockRetry` exists and several stores use it. It is the right tool where a deadlock cannot be designed out, such as concurrent inserts contending on secondary-index gaps. Here it can: the lock order is ours to choose, and choosing one removes the deadlock rather than recovering from it. A retry would also hide a later reordering, which is the defect this had in the first place.

## What this does not claim

Serializing rule changes per policy is a narrowing of concurrency, deliberately. Changes to different policies are unaffected, and the version counter already implied the sequence: this makes writers take their turn to join it rather than discovering the conflict after both have done work.

## Out of scope

- Policy-level mutations (`CreatePolicy`, `UpdatePolicy`, `DeletePolicy`), which touch one row and have no ordering to get wrong.
- Any change to what a rule mutation does, its audit trail, or the snapshot fan-out.
