-- +goose Up
-- Evaluations a rule GAVE UP on, beside the retries it waited through (issue #1158). retryable_misses counts attempts that could
-- not decide because a process record had not yet materialized and were re-run. It says nothing about the attempts that stopped
-- waiting: past the materialization grace a rule evaluates the event as if nothing matched, which is a detection that did not
-- happen and was, until this column, unrecorded anywhere. An operator could see a rule retrying and never see it failing.
--
-- Per attempt, like retryable_misses and evaluations: a replayed batch abandons again and adds again. Read it as a ratio to
-- evaluations, not as a count of distinct lost detections.
--
-- abandon_measured_evaluations is how many of the row's evaluations were made by code that counts abandons, and the read reports
-- materialization_abandoned only when it equals evaluations. That one comparison covers every way a zero could be unmeasured: rows
-- written before this migration, a rule that does not count its abandons, and a rolling upgrade where an older replica keeps adding
-- evaluations to a row a newer one created. Tracking NULL instead handles the first two and not the third, because the older
-- replica's upsert does not name the column and so leaves a partial count looking whole.

-- +goose StatementBegin
ALTER TABLE detection_rule_eval_stats
	ADD COLUMN materialization_abandoned BIGINT NOT NULL DEFAULT 0 AFTER retryable_misses,
	ADD COLUMN abandon_measured_evaluations BIGINT NOT NULL DEFAULT 0 AFTER materialization_abandoned;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE detection_rule_eval_stats DROP COLUMN abandon_measured_evaluations, DROP COLUMN materialization_abandoned;
-- +goose StatementEnd
