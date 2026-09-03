# A batch that cannot be processed stops stalling its host

Fixes #836.

## The defect

`Nack` returns a batch to the queue with `UPDATE event_queue SET processed = 0, claimed_at_ns = 0`. There is no attempt counter, no dead-letter and no abandonment, and the claim selects a host's work `ORDER BY timestamp_ns`. So a nacked batch is the oldest pending work for that host and the next claim takes it again.

A batch that fails DETERMINISTICALLY is therefore retried forever, and the consequence is not confined to it. Nothing newer for that host is ever claimed, so the process graph stops advancing and every detection rule stops seeing that host's activity. Detection ends for the host, not for the rule or the event that failed.

Nothing surfaces it. There is no counter and no log that separates "this host's batch has failed four thousand times" from "this host is quiet", and the only symptom is an absence of detections nobody is watching for. At 500ms per tick a failing batch is attempted roughly 120 times a minute, so the failure is fast, silent and unbounded at once.

#832 was one way to reach a deterministic persistence failure and is fixed. This is the class, and it matters more now than it did: #766 and #767 let operators load and author rule packs, which multiplies the ways a batch can fail the same way every time.

## Approach

Bound the retry, then set the events aside so the host's queue advances.

Two bounds, and both must be exceeded. `Nack` counts attempts and stamps when the batch first failed; a batch is set aside only once it has both exceeded the attempt bound AND been failing for longer than the duration bound.

- **20 attempts.** At a 500ms tick this is reached in about ten seconds, so on its own it would set aside anything that failed briefly. Its actual job is to rule out the other shape: a batch that failed once, then sat for a long time because the host went quiet, would exceed a duration bound on its second attempt.
- **15 minutes.** This is the bound that does the work. A transient condition lasting less than fifteen minutes never sets anything aside, and a host stalls for at most about fifteen minutes rather than indefinitely. It is three claim leases, which is the other timescale in this subsystem.

Neither is configurable. They are constants with their reasoning next to them, and can become configuration when a deployment needs different ones rather than in anticipation of that.

## Setting aside is not data loss, and that is what makes the trade acceptable

The ingest handler writes the **archive first** and the work queue second (ADR-0015). The archive is deduplicated by event id and retained independently on its own window, and it is what alert evidence and hunting queries read.

So an event whose queue entry is set aside is still there. What is given up is narrower and worth stating exactly: that event's contribution to the process graph, and its evaluation by detection rules.

The remaining cost is real and is not hidden. Claiming in timestamp order exists precisely so a host's stream is folded in order, and the in-flight floor in `ClaimForHost` carries a long comment about what happens when it is not: a later exec whose fork never arrived is folded as a fork-less exec, which is the duplicate-generation problem #717 removed. Setting events aside reintroduces exactly that hole, bounded to the events set aside.

That is the lesser harm by a wide margin. One host gets a gap of at most a bounded batch in its process tree; the alternative is that the same host contributes nothing to the graph and raises no detections at all, for as long as the condition lasts, with nothing to say so.

## Observability

`edr.events.set_aside`, carrying `host_id`, plus a log record naming the host and the batch. The counter answers "has any host stopped contributing", which is the alerting question, and the attribute is what makes it answerable per host: a fleet-wide total cannot say which host went dark.

The counter's name and attribute are pinned against the concrete recorder rather than only a fake. A fake proves the processor forwards a count to whatever recorder it holds, which a misspelled instrument name or a missing registration passes just as happily, and an alert authored against a name nothing emits reports a stalled host as silence.

Adding a counter means restating `Stable counter names`, and #838's gate requires every concurrent restatement of a requirement to be identical. Two in-flight changes already restate it, so this change updates all three to the same text. That is the cost that gate imposes, and this change is the first to pay it; the gate is what keeps it from being discovered at release instead.

## Bounded growth

`PruneProcessed` deletes only `processed = 1`, so set-aside entries would otherwise accumulate for the life of the deployment. They age out under the deployment's retention window, which also fixes the retention window as the period an operator has to inspect them.

Aged on when the entry was WITHDRAWN, stamped in its own column, not on when its batch first failed. The first version used the first-failure stamp and was wrong: attempts accrue only while a host is online, so a batch can first fail, sit through an offline stretch longer than the whole retention window, and only then reach the attempt bound, at which point it is withdrawn and swept on the next pass with no window to inspect it in. A laptop in a drawer for a month produces exactly that. The two clocks are separate columns because they answer separate questions, and the retention window is only meaningful measured from the moment there is something to look at.

## Rejected

**Delete the batch instead of setting it aside.** Simpler, and it throws away the record of which events were skipped for no gain, since the events themselves are in the archive either way. Keeping the entries costs one row each and names the exact events.

**Bisect the batch to find the poisonous event.** This would set aside one event rather than a batch, which is a smaller hole. It is also considerably more machinery on a failure path, and the batch is already small. Worth revisiting if the hole turns out to matter in practice; not worth it first.

**An attempt bound alone.** Rejected above: at 120 attempts a minute it converts every transient blip into a set-aside.

**Reusing the first-failure stamp for retention.** One fewer column, and it makes the operator's inspection window collapse to nothing for exactly the hosts most likely to need it. Covered above.

## Not in this change

An operator surface for reviewing or requeueing set-aside events. The counter and the log make the condition visible, which is what #836 identifies as the part that is clearly wrong today. A UI for acting on it is a separate piece of work with its own design, and it should be built against whatever #774's consumer half establishes for this kind of view.
