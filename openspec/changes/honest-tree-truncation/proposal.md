# Tell the analyst when the process tree is not showing everything

## Why

The process tree silently drops rows. `GetProcessTree` applies a server-side `LIMIT` (2,000 by default) and the response carries nothing but `roots`, so the UI renders whatever arrives with no indication that anything is missing.

Measured on a live host (`B7D79E29`, the OVH quickstart deployment) over a single **15-minute** window: **2,588** processes overlapped the window and the graph rendered **2,000**. The other ~588 were not filtered, not aggregated, and not reported. They were dropped, and the page looked complete.

This is a trust defect rather than a capacity one. An analyst who scopes a window and sees no `curl` concludes there was no `curl`. That conclusion is unsound today and nothing on the page says so. It also blocks honest messaging in every later story of epic #415: the interesting-branches-only default (#417) has to say "N of M interesting", and lazy expansion (#421) has to say what is not loaded yet. Both need a truthful denominator first.

## What changes

- **The tree response gains result metadata**: `total_matched` (every process row whose lifetime overlaps the window, independent of the limit), `returned` (the rows the limit actually admitted), and `truncated`.
- **The UI shows a banner when `truncated` is set**, naming both numbers and pointing at the two ways to fix it (narrow the window, or use search).
- **The window predicate becomes a single shared SQL fragment** used by both the row query and its `COUNT(*)` companion.

No change to which rows are returned, to aggregation, or to any existing field. This is additive.

## Why `returned` is carried rather than derived

The obvious objection is that a client already knows the limit it asked for, so `returned` is redundant and `total_matched` plus `truncated` would do. That is wrong on two independent counts, and both are silent:

- **The handler clamps.** A requested limit above `processTreeMaxLimit` is lowered, and a zero or negative one becomes the default. So the client's requested limit is not reliably the effective one, and a client computing `min(limit, total_matched)` prints a number the server never returned.
- **Aggregation means nodes are not processes.** By default repeated identical-path leaf siblings collapse into `×N` nodes (#416), so counting what is on screen does not recover the row count either.

A client that derives the numerator is therefore re-implementing two server-side decisions and getting them wrong in exactly the cases that matter. The banner exists to stop the page lying; deriving its numerator client-side would reintroduce the lie one layer up.

`truncated` is kept even though it equals `returned < total_matched`, because it states the server's own judgment rather than asking clients to infer it. Lazy expansion (#421) will truncate for a second reason (an unexpanded subtree, not a row cap), and a client keyed on the explicit flag keeps working when that lands.

## Why the count is unconditional

The fleet-wide process search skips its `COUNT(*)` for the fully-unfiltered browse and returns the `TotalNotCounted` sentinel, because counting the whole `processes` table is its expensive half. That rationale does not transfer: the tree read is always scoped to one `host_id` and one time window, which is the case the search's own comment calls "index-cheap" and for which it restores the exact count. So the tree always counts, and `total_matched` is always a real number. No sentinel, no client branch.

## Why one shared predicate

`total_matched` is only meaningful if it counts exactly the rows the SELECT would have returned without its limit. Two hand-maintained copies of a five-clause overlap predicate will drift, and the failure mode of drift is a banner that states a wrong number confidently, which is the same class of defect this change exists to remove. The predicate and its argument list therefore live in one place and both queries build from it, so a future edit to the window semantics cannot change one side only.

## Impact

- Affected specs: `server-rest-api` (Per-host process forest), `web-ui` (Process tree visualization).
- Affected code: `server/detection/api` (new result type, `Service.BuildTree` signature), `server/detection/internal/mysql` (shared predicate, new count), `server/detection/internal/graph`, `server/detection/internal/service`, `server/detection/internal/operator`, `ui/src/types.ts`, `ui/src/components/ProcessTree.tsx`.
- `Service.BuildTree` returns a result struct instead of a bare slice. Implementors and callers live inside the detection context plus its test doubles; there is no cross-context caller.
- Wire-compatible for existing clients: `roots` keeps its shape and position, and the three new fields are additive.
