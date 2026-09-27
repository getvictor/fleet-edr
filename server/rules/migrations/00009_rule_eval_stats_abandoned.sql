-- +goose Up
-- Evaluations a rule GAVE UP on, beside the retries it waited through (issue #1158). retryable_misses counts attempts that could
-- not decide because a process record had not yet materialized and were re-run. It says nothing about the attempts that stopped
-- waiting: past the materialization grace a rule evaluates the event as if nothing matched, which is a detection that did not
-- happen and was, until this column, unrecorded anywhere. An operator could see a rule retrying and never see it failing.
--
-- Per attempt, like retryable_misses and evaluations: a replayed batch abandons again and adds again. Read it as a ratio to
-- evaluations, not as a count of distinct lost detections.
--
-- NULL, with no default, so every row written before this column existed reads as NOT MEASURED rather than as zero. A zero there
-- would claim "gave up on nothing" for days no code was counting, and the tuning page would show that as a measurement for as long as
-- its window reached back past the upgrade. The upsert adds to the stored value, so the upgrade day's row, which already existed,
-- stays NULL too: NULL plus a count is NULL, and that day was only partly measured. The read reports a total only for a window whose
-- every row was measured.

-- +goose StatementBegin
ALTER TABLE detection_rule_eval_stats
	ADD COLUMN materialization_abandoned BIGINT NULL AFTER retryable_misses;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE detection_rule_eval_stats DROP COLUMN materialization_abandoned;
-- +goose StatementEnd
