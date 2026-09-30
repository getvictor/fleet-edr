# Count the evaluations a rule abandons

## Why

A rule that needs the process record an event names waits for it inside the materialization grace, re-running the batch, and then gives up: it evaluates the event as if nothing matched. The waiting is counted, as `retryable_misses`. The giving up was counted nowhere (issue #1158).

That is the wrong way round for a detection engine. A skipped evaluation is a detection that did not happen, and until now it was indistinguishable from a rule that matched nothing. The loss is already documented: the #661 post-mortem in `eval.go` records a real beacon alert that "was dropped for good" exactly this way.

Issue #1158 first read `dns_c2_beacon`'s 78.6% `retryable_misses` rate as evaluations being silently skipped. It is not: that counter measures retries that are re-run, and a replay counts again by design, so it is a churn ratio. The churn is real, but the drops were unmeasured, and there is no way to size the churn problem, or to know whether a change to it helped, until they are.

## What changes

The engine records, per rule and per process within a batch, every event a rule evaluated as a non-match because its process record never arrived. The count is stored beside `retryable_misses`, served on the evaluation-statistics endpoint, and shown in the detection tuning Cost column apart from the undecided count.

Four rules make this decision at a point where a missing record means "stop waiting": `dns_c2_beacon`, `suspicious_exec`, `application_control_block` and `application_control_would_block`. The three of them that were not yet scoped rules become scoped rules to reach the batch scope.

## What is deliberately not covered

- **Imported Sigma rules.** They share one memoized subject lookup per event, and a missing subject only affects a rule whose condition reads the process. Counting every consumer as abandoned would overstate the loss for rules whose decision never depended on it. Tracked separately.
- **`osascript_network_exec`.** It walks the process graph from the temp exec before resolving it, so a missing record ends the evaluation at the walk and the later resolution step is unreachable. Its young misses are therefore neither retried nor counted, which is a separate defect in the rule's resolution order. Tracked separately.

Both are stated in the requirement so a zero for those rules is not read as a measurement.

## Absent is not zero

A count is only a measurement where every evaluation behind it counted its abandons. Each stored row records how many of its evaluations did, and the count is reported only for a window where that equals the evaluations; otherwise it is omitted. That covers days before the upgrade, rules that do not count (the two above), and a rolling upgrade in which an older replica is still adding evaluations.

## Events with no process identifier

The four rules now skip an event with no pid before resolving its process, as the existing requirement "An event a rule cannot identify a subject for is skipped" already demands and as imported Sigma rules already did. They were looking up process zero instead, which retried the batch inside the grace and would now have been counted as an abandon past it. The requirement's wording is unchanged, so no delta restates it; the four rules gain tests carrying its scenario marker.

## Not changed

The grace windows, the retry behaviour, and each rule's decision on an event it can attribute are unchanged.
