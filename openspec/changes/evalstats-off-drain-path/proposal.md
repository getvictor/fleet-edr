# Take the per-rule evaluation-statistics write off the drain path

## Why

#833 landed durable per-rule evaluation statistics for #774. The counters were right and their cadence was not: the write ran synchronously once per event batch.

Two consequences, both from the table below. It capped ingest, because throughput saturates near 1800 writes/sec against a single MySQL and every replica contends on the same instance, so this bounded batches/sec for a whole deployment however many replicas were added. And it cost more than the work it measured: all 73 dispatched rules evaluated in roughly 1.2ms in total on the dev server, against a write of about 1.5ms at one writer and over 12ms at thirty-two.

Row-lock contention is not the mechanism, and that was tested rather than assumed. A host-derived shard column moved p50 not at all and left throughput flat, so it was reverted; do not re-add one without a measurement showing something different.

## What changes

Two tiers, neither on the drain path.

The durable table stays, because #774's acceptance criterion is that a noisy rule is identifiable from the UI WITHOUT querying a metrics backend. Only its cadence changes: a per-replica aggregator keyed by rule id, flushed on a ticker and on graceful shutdown. The drain path pays a mutex and a map update instead of a round trip, and the database sees one write per flush per replica.

Per-rule evaluation duration also becomes an OTel histogram, which is where "which rule is slow" is properly answered with percentiles. The project already routes metrics through OTel and this measurement bypassed it.

## Measured effect

All numbers from one committed harness (`server/rules/internal/tests/evalstats_latency_test.go`, run with `EDR_MEASURE=1`), stated once here rather than repeated per section, so a later edit cannot leave two versions of them:

| | p50 | p95 | p99 |
| --- | --- | --- | --- |
| before, per batch, 1 writer | 1.535ms | 3.403ms | 9.446ms |
| before, per batch, 32 writers | 12.656ms | 50.415ms | 70.751ms |
| after, per batch, 1 writer | 1us | 1us | 1us |
| after, per batch, 32 writers | 1us | 48us | 389us |

One flush of 73 rules costs about 1.5ms to 2ms, once per interval per replica.

The after-figure above is the buffer call ALONE, and review was right that a before/after claim has to include everything the drain path gained. The change also records one OTel histogram sample per evaluated rule: measured with a real SDK meter (a bare recorder has a nil instrument and would have measured nothing), that is 114us for a 73-rule batch, or 1.56us per rule. So the honest per-batch comparison is about 115us after, against 1.48ms at one writer and 12.98ms at thirty-two before.

Stated as a fraction of the work a batch does, which #837 notes was never established: a 100-event batch drains end to end, from ingest to acknowledged, in 39ms at p50 (`server/detection/internal/tests/batchtime_measure_test.go`). So the removed write was about 4% of a batch at one writer and about a third of it at thirty-two, and what replaced it is about 0.3%.

## Why buffering is acceptable here and would not be for match counts

The distinction is already in the spec rather than being re-argued. A monitor match is a fact about the world that drives a promotion decision, so losing one makes a rule look quiet and misleads the operator; that is why those are written only after the batch is acknowledged. An evaluation cost sample is one of thousands and losing a window changes no decision.

ADR-0010's carve-out covers the in-process state, and the annotation it requires is carried verbatim.

A transient database failure discards nothing: a failed flush returns its counts to the pending set and the next flush retries them. Because the set is keyed by rule id, a database that stays down grows the counts and never the map.

That retry is at-least-once against an additive write, so it is not free, and the conditions under which these numbers are inexact are enumerated in the requirement rather than here. Restating them in five places is what let them drift apart in one review round. #868 tracks making the write idempotent, which is what would remove the question.

## Rejected: sampling

Writing one batch in N is simpler, with no state, no flush loop and no shutdown ordering. It is wrong for the two most decision-relevant fields: retryable misses are rare, so sampling can miss them entirely, and the worst-case evaluation becomes the worst of the sampled attempts. The mean survives and the signal does not.
