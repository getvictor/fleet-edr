# Durable per-rule evaluation statistics

Closes the remaining half of #774.

## What already shipped

#774 asks for per-rule fire counts and evaluation latency, surfaced in the product rather than only in a metrics backend. The **fire count** half landed with #813: `detection_rule_match_counts` is written after acknowledgement, pruned on a retention sweep, read behind `GET /api/v1/detection-config/rule-match-counts`, and rendered in the detection-config UI as "approximately N matches on M hosts in the last D days". Its acceptance criterion, that a noisy rule is identifiable from the UI, is met today.

The other half is not built. Per-rule evaluation latency exists only as `detection.rule.evaluate` span duration, which is exactly the metrics backend the issue says an operator should not have to query, so a **slow** rule is invisible in the product. `edr.detection.materialization_retries` is a fleet-wide counter and cannot say which rule is churning. Evaluation count is only inferable by counting spans. There is no eval-stats-shaped table in any context.

## Approach

A sibling table to the one #813 established, rather than a second pattern.

`detection_rule_eval_stats` keyed **(rule_id, day)**, without the host dimension the match-counts table carries. That dimension is load-bearing there, because promotion turns on whether a rule is noisy on one host (wants an exclusion) or across the fleet (too broad). Latency is a property of a rule and its input volume, not of a host, so keeping the dimension would multiply the rows by the fleet size to answer a question nobody asks of it.

Columns: `evaluations`, `retryable_misses`, `eval_ns_sum`, `eval_ns_max`. Sum with count gives the mean and max gives the worst case, which is what finding a slow rule needs. Deliberately no buckets for percentiles: the spans already in the tracing backend answer p99 properly, and a second, worse histogram in MySQL is not worth the write cost on a path that runs once per rule per batch.

The engine appends one entry per rule to a per-call slice (a rule is evaluated exactly once per batch, so nothing needs merging there) and hands it to the recorder once per batch. The store folds that slice to one row per rule before the statement, since a fold is where the worst case has to be combined with a max rather than a sum. The result is a single multi-row upsert rather than a statement per rule, and the slice is per-call and discarded, so nothing shared is held between requests (ADR-0010).

## The counting rule, which is the opposite of the monitor-match rule

Monitor matches are recorded only after the batch is acknowledged, because a nacked batch is replayed whole and anything written during evaluation is written again on every retry; #631 measured roughly 130 retries a minute from one host. That discipline is right for matches and wrong here, and the difference is worth stating because it looks like the mistake:

A monitor match is a fact about the world. This rule matched this host on this day, and a replay must not make it two. An evaluation is a fact about work the server performed, and a replayed batch genuinely did evaluate again. Counting attempts also keeps the derived numbers honest: total time and attempt count inflate by the same replay factor, so the mean is unaffected, which is the same ratio argument that justified the per-attempt span attribute in #830.

Recording only after acknowledgement would also put the retryable-miss count out of reach, because a batch that ends in a retryable miss is never acknowledged. That counter is the point of this half of the issue: it is what identifies the rule whose misses are driving the retry churn.

## Scope of the requirement

The delta's requirement covers the durable record only, not presenting it to an operator. #774's acceptance criterion is about the UI, and this change ships no UI, so a requirement claiming the operator-facing outcome would be satisfiable while the operator still has nothing to read. The surfacing requirement and its scenario ship with the consumer change.

## Where the requirement lives

Under `observability-instrumentation`, beside "Monitor-mode matches are recorded durably per rule" (in-flight in `record-monitor-match-counts`), not under `server-detection-rules-engine`. Durable per-rule counters surfaced for operators are that capability's concern, and splitting the two halves of #774 across capabilities would leave a reader comparing them across files.

The two requirements state OPPOSITE recording rules, so the new one says so explicitly and says why, rather than sitting next to its sibling looking like a contradiction a reviewer has to resolve.

The sibling's "a monitor match is counted once across a replay" scenario is deliberately NOT restated here. That requirement already owns it, and duplicating a scenario across two in-flight deltas is how the release archive step silently drops one.

## Impact

- New table in the rules context, with a retention sweep alongside the existing match-count prune.
- The engine gains an optional stats recorder, injected the way the mode resolver and monitor-match recorder already are. Unset records nothing, so tests and the replay harness are unaffected.
- No change to monitor-match semantics.

Reading the statistics back over HTTP and rendering them in the detection-config UI is deliberately NOT in this change; it is the consumer half and ships next, so this one stays reviewable at roughly 800 lines.
