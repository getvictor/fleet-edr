-- +goose Up
-- Durable per-rule EVALUATION statistics (issue #774). The sibling table detection_rule_match_counts answers how often a rule
-- FIRES; this one answers how much work it costs and how often it cannot decide. Those are different questions and a rule can be
-- quiet and expensive: at a thousand rules neither is findable by reading logs, and today the only per-rule latency anywhere is
-- the detection.rule.evaluate span duration, which lives in the tracing backend the issue asks operators not to have to query.
--
-- Keyed (rule_id, day) WITHOUT the host dimension the match-counts table carries. That dimension is load-bearing there, because a
-- promotion decision turns on whether a rule is noisy on one host (which wants an exclusion) or across the fleet (which means the
-- rule is too broad). Latency is a property of a rule and its input volume, not of a host, so keeping the dimension would multiply
-- the rows by the fleet size to answer a question nobody asks of it.
--
-- Day granularity for the same reason as the sibling: the useful figure is a rate over a window, and day buckets bound the table by
-- (rules that evaluated) x (retained days) rather than by event volume.
--
-- Sum and count rather than histogram buckets: sum/evaluations is the mean and eval_ns_max is the worst case, which is what finding
-- a slow rule needs. Percentiles are answered properly by the spans already in the tracing backend, and a second, worse histogram
-- in MySQL is not worth the write cost on a path that runs once per rule per batch.
--
-- No foreign keys, for the same reason as the sibling: rule_id names a rule in the in-memory catalog, not a table.

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS detection_rule_eval_stats (
	-- VARCHAR(255), NOT the VARCHAR(64) every other rule_id column in the repo uses, and the difference is deliberate rather than
	-- sloppy. The imported SigmaHQ rules (#764) derive their ids from upstream filenames, and one of them,
	-- proc_creation_macos_remote_access_tools_teamviewer_incoming_connection, is 70 characters. A 64-char column truncates it, and
	-- MySQL in strict mode rejects the write outright: measured on the dev server, this table's very first real write failed with
	-- "Data too long for column 'rule_id' at row 43" across all 73 dispatched rules.
	--
	-- This table is the one that exposes it, because it records every rule that EVALUATED where the others record only rules that
	-- matched, were configured, or alerted. The same latent defect sits in alerts, detection_rule_settings and
	-- detection_rule_match_counts, which is a separate fix on tables that already hold data (issue filed); widening here is not it,
	-- and matching their 64 would only mean this table failed too.
	rule_id          VARCHAR(255) NOT NULL,
	-- The UTC day the evaluations fell on, from the server's clock. DATE because the column IS the bucket.
	day              DATE        NOT NULL,
	-- Evaluation ATTEMPTS, not logical batches. A nacked batch is replayed whole and really does evaluate again, so a replay adds
	-- to this. That is the opposite of the match-counts rule and is deliberate: see the store's doc comment for why, and note that
	-- eval_ns_sum inflates by the same replay factor, so the mean the two produce together is unaffected.
	evaluations      BIGINT      NOT NULL DEFAULT 0,
	-- Attempts that ended in ANY retryable outcome, not just an unmaterialized subject process. The engine counts every error
	-- wrapping the retry sentinel, which includes a rule deliberately waiting rather than missing data: sensor_tamper waits out a
	-- recovery window and reports the generic form. So this is "could not decide, batch will be replayed", which is the quantity
	-- an operator wants when asking which rule drives the churn; reading it as a per-rule materialization counter would
	-- misattribute a rule that is working as designed (issue #833 review).
	--
	-- Recorded even though such a batch is never acknowledged, which is exactly why: gating on the acknowledgement would leave
	-- this column permanently zero, since the only batches that could report a retryable outcome are the ones that never reach an
	-- acknowledgement.
	retryable_misses BIGINT      NOT NULL DEFAULT 0,
	-- Total and worst-case wall time across those attempts, in nanoseconds. BIGINT holds ~292 years of nanoseconds, so a day's
	-- accumulation cannot approach it.
	eval_ns_sum      BIGINT      NOT NULL DEFAULT 0,
	eval_ns_max      BIGINT      NOT NULL DEFAULT 0,
	first_seen       TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
	last_seen        TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
	PRIMARY KEY (rule_id, day),
	-- The prune sweep deletes by age across every rule, so it needs a day-leading index of its own.
	INDEX idx_detection_rule_eval_stats_day (day)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS detection_rule_eval_stats;
-- +goose StatementEnd
