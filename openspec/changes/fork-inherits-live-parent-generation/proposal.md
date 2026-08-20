# Inherit a fork's path from the newest parent generation that had forked by then

## Why

A fork-without-exec child has no image of its own, so the graph builder gives it the parent's path. It resolved that path by PID alone: newest generation of that PID by fork time, no bound at all. The answer is therefore "whatever holds this PID at the moment the fork happens to be materialized", which is not the same question as "what was this child's parent running".

The two answers diverge whenever a fork is materialized after its parent's PID has been recycled, and that is routine rather than exotic. The extension stamps events at handler time, and concurrent claim batches (issue #535) hand the pipeline a later batch's events before an earlier one's, so a successor generation of the parent PID can reach the forest first. The child then names a binary its parent never ran (issue #714). Every reader of the forest is affected, because the wrong path is persisted on the row rather than computed at read time: the process tree labels the node with it, the process detail shows it, and the detection rules that gate on `proc.Path` judge the child against the wrong image.

Measured against the dev database, 750k process rows, over the 154,660 rows that never exec'd and so carry a purely inherited path: 21,084 of them (13.6%) name a binary from a generation that had not yet forked when the child did. Five rows have no candidate generation at all.

The sibling lookup in the same store, `GetProcessByPID`, brackets both ends of the lifetime, and the graph builder's in-memory batch overlay mirrored the unbracketed query faithfully, so the batched path (the production one) and the per-event path agreed on the wrong answer. The store's doc comment meanwhile claimed the function returned the generation "still alive (or was alive most recently)", which no part of the code did.

## What changes

- The inherited path is resolved at the fork's own timestamp: the newest generation of the parent PID that had forked at or before it. `GetParentPath` takes that instant and applies `fork_time_ns <= ?`.
- The batch overlay applies the identical bound. An overlay that kept the old predicate would have reintroduced the defect for every batch larger than one event, which in production is every batch.
- A child whose parent PID had no generation at all by then inherits nothing. That is the only case that yields an empty path, and it is 5 rows in 154,660.
- The bulk preload keeps loading every row for each key, including exited ones, and its comment now says why: the reads are bounded by the READING event's timestamp, not by now, so an older generation is still the right answer for an older event.

## What deliberately does not change: no aliveness test

The first cut of this change also required the parent to be recorded as alive at the fork instant, mirroring `GetProcessByPID`'s `(exit_time_ns IS NULL OR exit_time_ns >= ?)`. That was wrong and is not shipped. The two lookups ask the same question about different instants, and only one of them has a physical guarantee behind it:

- `GetProcessByPID` resolves an arbitrary instant that arrives from an unrelated event, typically a network flow's timestamp. A generation that had already exited genuinely must not match, so it needs both bounds.
- `GetParentPath` resolves a fork, and a parent is alive at its child's fork by construction. Nothing forks from a dead process. So an aliveness test can never correct an answer here; it can only discard the only candidate, and it discards it on the strength of an exit timestamp.

Those timestamps are the least reliable field involved. The extension stamps at handler time (issue #710, measured 701ms late), and `CloseStaleProcess` synthesizes an exit at the recycling fork's timestamp. When the record says a parent exited before its own child forked, the record is wrong, not the parent.

Measured over the same 154,660 rows, the aliveness test is a net loss of about 4:1:

| Variant | Paths corrected | Paths blanked |
| --------------------------- | --------------: | ------------: |
| Fork bound only (shipped)   |          21,084 |             5 |
| Fork bound plus aliveness   |          17,671 |        29,880 |

29,875 of those 29,880 blankings are the aliveness test's alone. It also corrects 3,413 FEWER rows than the fork bound by itself, because it blanks rows it could have corrected. Of the rows it would blank, 29,457 had a parent whose newest recorded generation was stamped as exited more than an hour before the child forked, and the worst by 9.2 days, which is the signature of a true parent generation that was never captured rather than of a near miss: only 35 rows sit within a minute, the range where handler-time skew alone could account for it.

Those stale-parent rows are the honest limit of this change. Where the child's real parent generation was never recorded, the fork bound answers with the newest generation that WAS recorded, which is the best available evidence and is the same answer the code gives today. It does not claim to be the right binary; it claims not to be a binary that provably did not exist yet, which is what issue #714 is about.

The asymmetry is recorded in a comment at both call sites, because it reads as an inconsistency and a future reader would otherwise remove it and reinstate the regression.

## Non-goals

- No migration or backfill. Rows already written with a wrong inherited path stay as they are; the fix applies to forks materialized from here on. Backfilling would mean re-deriving each fork's parent generation from history, which is a separate change with its own correctness argument.
- The duplicate and orphan generations visible in the issue #714 report are the per-host claim affinity defect (issue #717) and were fixed separately.
- The ESF handler-time stamping that produces the reordering is issue #710 and is untouched here. This change makes the forest correct under reordering rather than removing the reordering.
