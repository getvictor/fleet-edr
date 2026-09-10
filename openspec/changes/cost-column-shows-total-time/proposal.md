# Cost column reports total time, not only a per-attempt mean

## Why

The detection tuning table's Cost column shows a mean wall time per evaluation attempt and sorts on it. A mean with no volume behind it does not answer the question the column exists for, which is which rule is costing the server enough to be worth tuning.

Measured on the demo's 76 rules over 7 days:

| rule | mean | evaluations | total |
| --- | --- | --- | --- |
| `dns_c2_beacon` | 43.47ms | 25 | 1086.8ms |
| `sudoers_tamper` | 4.28ms | 1 | 4.3ms |
| `suspicious_exec` | 2.49ms | 24 | 59.7ms |

Sorting by mean puts `sudoers_tamper` third on the page. It ran once, and cost 4.3ms in the whole window. `suspicious_exec` ranks below it having cost fourteen times as much. An operator following that ranking tunes the wrong rule.

The figure is already stored: `detection_rule_eval_stats.eval_ns_sum` is what the mean is derived from, so the total is one more `SUM` over rows the query already reads, and is exact rather than reconstructed from a rounded mean.

## What changes

- `RuleEvalSummary` gains `total_eval_ns`, summed from the same daily rows the mean is derived from.
- The Cost cell leads with the total for the window and keeps the mean as its secondary figure, matching how the Observed cell leads with matches and carries hosts behind it.
- Sorting the Cost column orders by total rather than by mean.
- The column note says which figure is which.

## What does not change

The mean stays visible, and the worst case stays in the hover. A rule that is usually fast and occasionally terrible is still a real answer, and the mean is still the figure that identifies a rule expensive on every attempt rather than one with a single bad batch.

## Impact

- Affected specs: `web-ui`
- Affected code: `server/rules/api/evalstats.go`, `server/rules/internal/detectionconfig/evalstats.go`, `ui/src/api.ts`, `ui/src/components/DetectionConfig/DetectionConfig.tsx`
