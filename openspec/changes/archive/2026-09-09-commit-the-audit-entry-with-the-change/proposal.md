# Commit the audit entry with the change it records

## Why

Both rule-content services wrote their audit row AFTER the content transaction committed, and logged rather than returned a failure to write it (#886). That leaves a window in which a fleet's detections changed durably and nothing in the audit log names who did it or why.

The ordering was the lesser of the two outcomes then available rather than an oversight. Returning the error would report failure for a change that had already happened, and an operator told their rollback failed, whose rules have in fact been replaced, acts on a false belief. The rollback is the widest case: it replaces every shipped rule at once.

One transaction covering both was not reachable, because the audit store sits behind an interface the identity context owns and a rules-context service cannot enlist it in rulecontent's transaction (ADR-0021).

## What changes

A transactional outbox, which is the repository's existing answer to committing a side effect with the transaction that caused it: `webhook_delivery` (#496) is the same shape.

The entry is written into `rule_content_audit_outbox` inside the transaction that makes the content change, so it commits if and only if the change does. A drain in the rules context turns entries into audit rows: immediately, on the request that wrote one, and on a sweep for the ones a crash or a database blip left behind.

The payload is **opaque** to rulecontent, which is what keeps the boundary intact. That context stores bytes it does not interpret; the rules context encodes and decodes them and is the only thing that knows what an audit event is.

The entry is built by a callback rather than passed in, because the facts worth recording are computed inside the call: the version a change produces is the base it was validated against plus one, and the warnings are narrowed to the document under change. Passing a value in would mean either duplicating that logic a layer up or recording a weaker row than the one this replaces.

## Impact

- The guarantee changes from "the change is recorded unless the audit write fails" to "the change and its record commit together, and delivery is retried until it succeeds".
- Delivery may lag the change. In the ordinary case it does not: the request that made the change delivers it before returning.
- A rule-content audit row no longer carries a trace id. The recorder fills that from the call's context, and the drain's context is the sweep's rather than the operator's request, so carrying one would attribute the row to the wrong call. This is a real loss against the synchronous write and is the trade the outbox makes.
- Delivery is at-least-once: an entry is deleted only after the recorder reports success, so a crash between the two redelivers. A duplicate audit row is visible and a missing one is not, which is the right direction for an append-only trail.
