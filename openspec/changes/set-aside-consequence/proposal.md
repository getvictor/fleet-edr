# The set-aside record states the consequence that actually applies

## Why

The record written when a batch is set aside told an operator to go and look at the wrong thing.

Setting events aside happens at two stages of processing a host's claimed work, and both wrote "this host has a gap in its process graph". For one of them that is false. `processHost` completes the graph builder before it evaluates, so a batch withdrawn during evaluation is already materialised: its process tree is intact, and what was lost is the rest of the rule evaluation. An operator following that record inspected a process tree, found nothing wrong, and had nothing else in the line to go on.

Being wrong in this direction is worse than saying nothing. The record exists because a stalled host is otherwise indistinguishable from a quiet one, so it is the only prompt anyone gets; a prompt pointing at healthy data spends the responder's attention and teaches them to discount the next one.

## What Changes

- The consequence is selected by the stage, so the builder stage reports a gap in the process graph and the detection stage reports that rule evaluation did not complete.
- The log MESSAGE stays fixed and the consequence rides on an attribute, so the line stays greppable and an alert authored on it keeps matching.
- The stage is a constant at both call sites rather than a string literal, because the stage now selects the consequence and a typo would quietly report the wrong one.
- The metric and port documentation describing what a set-aside means are corrected the same way, since they carried the same unconditional claim.

## Impact

- Affected specs: `server-event-ingestion`
- Affected code: `server/detection/internal/pipeline/processor.go`, `server/metrics/metrics.go`, `server/detection/api/service.go`
