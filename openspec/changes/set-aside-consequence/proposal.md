# The set-aside record states the consequence that actually applies

## Why

The record written when a batch is set aside told an operator to go and look at the wrong thing.

Setting events aside happens at two stages of processing a host's claimed work, and both wrote "this host has a gap in its process graph". For one of them that is always false, and for the other it is a certainty the system does not have. `processHost` returns before evaluation when the fold failed, so a batch withdrawn at detection was materialised first: its process tree is intact, and what was lost is the rest of detection. An operator following that record inspected a process tree, found nothing wrong, and had nothing else in the line to go on.

Being wrong in this direction is worse than saying nothing. The record exists because a stalled host is otherwise indistinguishable from a quiet one, so it is the only prompt anyone gets; a prompt pointing at healthy data spends the responder's attention and teaches them to discount the next one.

## What Changes

- The consequence is selected by the stage, so the builder stage reports a POSSIBLE gap in the process graph and the detection stage reports that detection did not complete, so alerts those events would have raised may be missing.
- The builder consequence is hedged because the certain form is reachable. Retry bounds accrue on the queue entry and count every attempt whichever stage failed, so a batch can fold, fail at detection, and be withdrawn later on an attempt whose fold failed. Those events are in the graph already, and nothing records that they got that far.
- The detection consequence names the outcome rather than the step that failed. A rule's own error is swallowed for per-rule isolation and never leaves the engine; what reaches the withdrawal is an alert-persistence failure, which aborts at the finding it happened on and leaves later rules unrun, or a retryable miss that ran out of attempts. Naming rule evaluation would be false for the first and would point an operator at rule execution while the failure was in alert storage.
- The log MESSAGE stays fixed and the consequence rides on an attribute, so the line stays greppable and an alert authored on it keeps matching.
- The stage value CARRIES its consequence rather than being mapped to one. A named string type was the first attempt and does not do the job: Go assigns an untyped literal to one happily, so a misspelling compiles and the lookup then treats every value that is not the builder as detection.
- Every other place describing what a set-aside costs is corrected the same way. The claim had been restated unconditionally in the metric description and its rationale, the recorder, the detection port, the queue-prune runner, the event-log port, and the store; the store and the ports are stage-agnostic, because Nack is called from both stages and that layer cannot see which.

## Impact

- Affected specs: `server-event-ingestion`
- Affected code: `server/detection/internal/pipeline/processor.go`, `server/detection/internal/pipeline/queueprune.go`, `server/detection/api/service.go`, `server/metrics/metrics.go`, `server/visibility/api/eventlog.go`, `server/visibility/internal/eventlog/store.go`
