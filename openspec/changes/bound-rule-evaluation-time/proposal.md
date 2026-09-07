# A rule that is too slow stops being evaluated, and says so

Part of #767. Follows #852, which bounded what an author can impose by estimating a pattern's cost.

## Why an estimate is not enough

#852's bounds are proxies. Each one is measured, and a proxy still cannot anticipate the combination an author writes, and it deliberately does not bound the event side at all: a field's values are compared against every value an event supplies, and comparing one costs in proportion to the EVENT's string rather than the author's. Both were measured as event-bounded there and left to this change.

This measures the thing itself. The engine already times every rule evaluation and records it per rule per batch, so what is missing is not measurement but a consequence.

## What the budget is set from

Real per-rule statistics from dev traffic, 219 evaluations across the vendored corpus:

- Mean evaluation: **0.094ms**.
- Worst legitimate single evaluation: **17.8ms**, `proc_creation_macos_remote_access_tools_teamviewer_incoming_connection`.
- Next worst: 1.24ms.

A pattern at #852's per-pattern limit costs about 4ms per event, and a batch is up to 100 events, so a rule that sits at that limit reaches roughly 400ms per batch.

**100ms per evaluation** therefore sits about 5.6x above the worst rule that is doing legitimate work, three orders above the mean, and comfortably below where an unaffordable rule lands. Same reasoning as `maxConditionDepth`: far above real content, far below where it hurts.

## Two bounds before skipping, not one

A single slow evaluation is not evidence. A cold cache, an unusually large batch, or a host that just enrolled all produce one, and the 17.8ms above came from a rule whose only two evaluations were both slow, which is exactly the shape a small sample produces.

So a rule is skipped only after **20 overruns within 15 minutes**, following #836, which reached the same conclusion for the same reason on the queue's retry bound. Twenty bounds the wasted work before a skip to about two seconds, and the window is what makes the count mean "repeatedly, lately" rather than "eventually": without it, a rule that ran slow twenty times over a month would be skipped on the strength of a condition that had long passed. An evaluation inside the budget clears the run, so a rule that is occasionally slow and usually fine never accumulates.

## The skip is not a mode change

A rule's mode is what the operator wants. A skip is what the server is doing to protect itself. Writing an overrun into the mode would make `GET /api/rules` report `disabled` for a rule nobody disabled, which is a lie about intent at any scope, and it raises who may undo it.

So the budget touches neither the mode nor `RuleModeSource`. The skip is per-replica and in-process, a cache that is safe to lose in ADR-0010's sense: each replica protects itself against the load it actually sees, and a restart clears it, which is the right default for a heuristic. If the rule was slow because of one pathological stretch, the next start gives it another chance.

## The overrun must not look like a failure

This is the trap the code makes easy to fall into. In `Evaluate`, a rule error that does not wrap `ErrRetryBatch` returns from the batch, and the batch is then nacked and replayed. A slow rule reporting failure would therefore make the batch retry, hit the same slow rule, and retry again: #836's stalled host reached by a new route.

So an overrun records and continues. The findings the evaluation did produce are kept, the batch proceeds, and the skip applies to LATER batches.

## Rejected

**A per-evaluation timeout that cancels the rule mid-flight.** It would need every rule to honour cancellation promptly to be worth anything, and a rule interrupted partway has produced findings it cannot report consistently. Measuring after the fact costs one comparison and needs nothing from rule authors.

**Skipping on the first overrun.** Rejected above: the measurement says a legitimate rule can take 17.8ms and a small sample can make that look typical.

**Persisting the skip.** It makes the server a writer of operator-facing configuration and outlives the condition that caused it. #851 already carries the question of what cross-replica state this class of decision should have.
