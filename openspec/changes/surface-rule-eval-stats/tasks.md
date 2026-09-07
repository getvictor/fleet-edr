# Tasks

## 1. Read path

- [x] 1.1 Pass the recorded statistics through the detection-config service to the operator API.
- [x] 1.2 Gate the route with the same action as the rest of that surface, and cap the window with the deployment's retention.
- [x] 1.3 Echo the window actually served, so a caller that asked for more than retention holds is told what it is reading.
- [x] 1.4 Specify the route and its response shape in the OpenAPI document, and sync the served copy.

## 2. Surface

- [x] 2.1 Read the statistics from the client with the same validation the match-count read uses, including a floor on attempts, since the mean is a division by that number.
- [x] 2.2 Add a Cost column beside Observed: mean per attempt displayed, worst case and undecided-attempt count in the cell's label.
- [x] 2.3 Keep the three states distinct, so a failed read reads as unavailable rather than as a cheap rule.
- [x] 2.4 Keep the two reads independent, so one failing does not blank the other.

## 3. Tests

- [x] 3.1 Handler: the window reaches the store, the served window is echoed, the retention cap applies to the default as well as to an explicit request, and a store failure is a 500 that does not leak the error.
- [x] 3.2 Client: every malformed envelope and row shape is rejected, each fixture malformed in exactly one way.
- [x] 3.3 Component: the unit follows the magnitude, undecided attempts are annotated only when there are some, and both unavailable states render as unavailable rather than as absence.
- [x] 3.4 Component: BOTH directions of the independence claim, since only-Cost-fails passes against a shared flag and only-Observed-fails is what catches it.
- [x] 3.5 Derive the authorization-deny table from the routes actually registered, so a route added without a row fails instead of going silently untested. That is how this route's own gate went uncovered.
- [x] 3.6 Fuzz both `days` parsers together as an equivalence, since they are one policy stated twice and the risk is drift rather than either mishandling a number.
- [x] 3.7 Label the undecided count for what the engine records: the counter increments at the miss, before anything knows a retry follows, so a batch that is set aside has its last miss counted with no retry after it.
- [x] 3.8 Reject a row that is well-typed and still impossible: more undecided attempts than attempts, or a mean above the maximum it is drawn from. Both sides of each come from the same rows in the store, so either means the response is not what it claims.
- [x] 3.9 Reuse the existing recording Router rather than writing a second one, and name the cap setter for the retention it reads rather than for one of the two reads it bounds.
- [x] 2.5 Let the table be sorted by cost, so the column answers which rule to look at rather than only what one rule costs. The server already returns the statistics slowest-first; keying them by rule id to render them beside their rule is what discards that.
- [x] 3.10 Put the numeric bounds the client enforces into the published schema too, so a generated validator does not accept rows the client refuses.
- [x] 2.6 Drop the statistics on a failed read rather than keeping them. The cells short-circuit before reading them, so the staleness is invisible everywhere except the sort, which is the one place an operator would act on it.
- [x] 3.11 Bound the published numbers at the largest integer a JSON parser round-trips, since `int64` promises a range the wire format cannot carry and the client is right to refuse it.
- [x] 2.7 Turn the sort OFF when there is nothing to sort by, not merely clear the data. A sort left switched on announces an order it is no longer producing, which is untrue rather than stale.
- [x] 3.12 Carry the undecided count in the label even at zero, since that is where the figure is promised; only the visible annotation is suppressed, for width.
- [x] 3.13 Collapse the two `days` parsers onto one core with thin typed wrappers, following `parsePositiveInt64Path` and its two wrappers in the same package. The typed wrappers are what keep the window types from being interchangeable; a shared implementation never was in tension with that, and the fuzz test now guards a seam rather than a duplicate.
- [x] 3.14 Hoist the wire-validation primitives both row validators build on, so a change to what counts as an acceptable number or timestamp cannot land on one adjacent endpoint and not the other.
- [x] 2.8 Treat an EMPTY successful read as unsortable too, not just a failed one. It is a different state to report and equally nothing to sort by, and it is what a fresh deployment shows.
- [x] 3.15 Reach that state with the sort ALREADY on. Asserting it from a cold start cannot fail: aria-sort is "none" and the control disabled for the ordinary reason, whatever the condition says.
- [x] 3.16 Put the cost caveat in a visible note beside the Observed one, since a `title` on a non-focusable header only reaches a pointer.
- [x] 3.17 Extend the server-level wiring test to the second read, since one setter now narrows both caps and the operator-package tests set them directly: a cap nothing ever narrowed would report 30 days over 7 and every one of those tests would still pass.
