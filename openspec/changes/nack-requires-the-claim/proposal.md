# Returning a batch to the queue requires the claim too

## Why

Acknowledging a batch has been conditional on still holding the claim since #817. Returning one was not: it matched on an event's STATE, which is a different question, and the two are the same defect on the two transitions.

So an attempt whose processing outran its five-minute lease could return events a replacement had since claimed. What that costs was understated until this change measured it against the current code:

- It resets the replacement's claim, and the replacement's acknowledgement is conditional on that claim, so the acknowledgement is refused and its work is redone by whoever claims the events next.
- It counts an attempt against events that did not fail for the attempt that owns them. The count lives on the event and ends in the event being withdrawn from processing entirely, so ordinary failures can leave an event one attempt short of that and a stale return supplies the last one.

The window is narrow by construction, since reaching it needs processing slower than the whole lease, and the defect predates the bound that withdraws events. It became worth closing because two other changes had to document it as a limit on what they promise: the retry bound (#836) and the monitor-match count carried to a withdrawal (#843).

## What changes

- Returning a batch takes the claim stamp the claim issued, as acknowledging already does, and acts only on the events that claim still holds.
- Ownership is established by reading the held events under lock before anything is written, rather than by a predicate on the writes. The writes cannot express it: the reset clears the stamp, so it cannot both check it and report which events it checked, and the withdrawal runs on events in the pending state, which is where an event another attempt returned also sits.
- Every statement then keys on that set. Checking ownership and then acting on the events that were ASKED for would leave the same defect in a narrower window, which is exactly the shape a batch takes when a lease expires under part of it.

An attempt that holds none of the events is told it no longer held the claim, as an acknowledging attempt is, and that is logged. Reporting only that nothing was withdrawn would be the same answer a held batch gets when no event reached its bounds, which would have made returning a batch the one way to lose a claim silently. It is still not an error: losing a claim is a normal outcome of a lease being exceeded, and the attempt that holds it carries on.

## Impact

- Affected specs: `server-event-ingestion`
- Affected code: `server/visibility/api/eventlog.go`, `server/visibility/internal/eventlog/store.go`, `server/detection/internal/pipeline/processor.go`
