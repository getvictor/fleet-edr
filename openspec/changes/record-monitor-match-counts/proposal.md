# Record monitor-mode matches durably, once per accepted batch

## Why

Issue #813, second of three. #812 registered sixty-six rules in monitor mode. A match produces an OTel counter increment and a DEBUG log, and nothing else: an operator deciding whether to promote a rule has to read a metrics backend, or grep server logs, to learn what the rule has been doing. Sixty-six rules are recording matches nobody can read in the product.

The counter also could not be trusted as a rate. It incremented while the batch was evaluated, and a batch that fails is nacked and replayed whole, so a retried batch counted its matches once per attempt. #631 measured roughly 130 materialization retries a minute from a single host under a sustained condition, so that is not a rounding error on the number an operator would use to decide whether a rule is affordable.

## What changes

Monitor matches are aggregated per (rule, host, severity) while a batch evaluates, returned to the pipeline, and recorded only once the batch is acknowledged. A nacked batch is replayed and counted once by whichever attempt succeeds. The same tally drives both the durable counter and the OTel series, so the two agree rather than being two numbers of different precision for one thing.

Durable counts live in MySQL in the rules context, keyed `(rule_id, host_id, day)`. ADR-0015 decides the store rather than convenience: it scopes ClickHouse to the raw event archive and keeps "the entire control plane", naming the rules context, in MySQL. A per-rule counter that informs a configuration decision is control-plane data. The host dimension is what lets a reader tell a rule that is noisy on one machine from one that is too broad everywhere, which are opposite remedies.

Pruning runs on a plain ticker rather than a leader-gated sweep. Every `RunIfLeader` loop holds its advisory lock, and therefore a pooled connection, for the life of the process, and the processor sizes itself against what those leave (#722). Paying a permanently held connection to serialise an idempotent DELETE would be the wrong trade.

## Impact

A new table in the rules context, subject to the existing `RetentionDays` knob. `MetricsRecorder.MonitorMatched` takes a count, because the caller now aggregates a batch before recording it. The "NOT deduplicated" caveat that #812 attached to `edr.detection.monitor_matches` is superseded and corrected in that change's own delta, since it describes behaviour this change replaces.
