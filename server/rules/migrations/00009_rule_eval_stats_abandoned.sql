-- +goose Up
-- Evaluations a rule GAVE UP on, beside the retries it waited through (issue #1158). retryable_misses counts attempts that could
-- not decide because a process record had not yet materialized and were re-run. It says nothing about the attempts that stopped
-- waiting: past the materialization grace a rule evaluates the event as if nothing matched, which is a detection that did not
-- happen and was, until this column, unrecorded anywhere. An operator could see a rule retrying and never see it failing.
--
-- Per attempt, like retryable_misses and evaluations: a replayed batch abandons again and adds again. Read it as a ratio to
-- evaluations, not as a count of distinct lost detections.
--
-- NOT NULL DEFAULT 0, so existing rows read as "nothing recorded" rather than NULL. That is honest for them: no code recorded
-- abandons when they were written, so zero is the only value the history supports, and the column's meaning starts at deploy.

-- +goose StatementBegin
ALTER TABLE detection_rule_eval_stats
	ADD COLUMN materialization_abandoned BIGINT NOT NULL DEFAULT 0 AFTER retryable_misses;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE detection_rule_eval_stats DROP COLUMN materialization_abandoned;
-- +goose StatementEnd
