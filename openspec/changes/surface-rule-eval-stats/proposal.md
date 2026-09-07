# Show what each rule costs, beside the rule

## Why

Closes #774. Its server half already shipped: #837 records per-rule evaluation attempts, undecided attempts and timings durably, off the drain path. What it explicitly did not do is present them, and the recording requirement says so in as many words, that presenting the figures is a separate requirement shipping with the surface that presents them.

Until that surface exists the record answers nothing. The issue's own acceptance criterion is that a noisy or slow rule is identifiable from the UI without querying a metrics backend, and today it is not: the figures are in MySQL and nothing reads them.

The match counts, which do have a surface, cannot stand in. They answer how NOISY a rule is. A rule can be perfectly quiet and still be the one holding up the drain loop, and at a thousand rules that rule is unfindable by reading logs.

## What changes

- A read route on the detection-config surface returns per-rule evaluation statistics over a window, gated by the same action as the rest of that surface and capped by the same retention.
- The detection-tuning table gains a Cost column beside Observed: mean time per attempt, with the worst case and the undecided-attempt count reachable from the cell.
- The two columns fail independently, so an outage in one does not blank the other.

## Impact

- Affected specs: `observability-instrumentation`
- Affected code: `server/rules/internal/detectionconfig/`, `server/rules/internal/operator/`, `docs/api/openapi.yaml`, `ui/src/api.ts`, `ui/src/components/DetectionConfig/`

The mean is displayed and the maximum rides in the cell's label, which is a deliberate choice about what the column is for. Scanning a column of maxima finds the rule that had one bad batch; scanning means finds the rule that is expensive every time, which is the one an operator is hunting. The maximum still has to be reachable, because a rule that is usually fast and occasionally terrible is a real answer, so it is in the label rather than dropped.

Attempts are reported rather than batches, matching how they are recorded: a replayed batch really did evaluate again, and contributes its own duration. The mean therefore stays a mean per ATTEMPT and is not inflated by replay the way a per-batch figure would be, since the count and the total grow together; an individual replay still moves it in whichever direction that attempt differed. The column says what it is counting so the number is not read as a fire count.
