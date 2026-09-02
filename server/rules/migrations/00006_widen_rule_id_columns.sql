-- +goose Up
-- Widen the rules context's three rule_id columns from VARCHAR(64) to VARCHAR(255), matching api.MaxRuleIDLen (issue #832). The
-- alerts table is the fourth and is widened by the detection context's own migration corpus; see there for the full reasoning and
-- for why the algorithm is stated explicitly.
--
-- Of the three, detection_rule_match_counts is the one already losing data: a monitor-mode match by the 70-character imported rule
-- fails to record, and the recorder logs and drops that failure by design, so #813's promotion evidence is silently absent for
-- exactly the rule an operator is trying to judge. The other two fail only when an operator configures that rule, which is the
-- same action the missing evidence is meant to inform.
--
-- All three accept INPLACE / LOCK=NONE at the wider size, verified against the pinned MySQL 8.4.9, so no index key exceeds
-- InnoDB's limit once widened: detection_rule_match_counts carries rule_id in its primary key alongside host_id, and the other two
-- carry it in a secondary key.
--
-- detection_exclusions carries its DEFAULT '' forward EXPLICITLY. MODIFY COLUMN restates a column's whole definition, so a plain
-- widening drops the default silently; that sentinel is load-bearing, since migration 00002 uses the empty string rather than NULL
-- for the fleet-wide row so the (rule_id, host_group_id) uniqueness stays honest. Dropping it was reproduced on a dev database
-- before this was written, which is the only reason it is not a defect in this migration.

-- +goose StatementBegin
ALTER TABLE detection_rule_settings MODIFY COLUMN rule_id VARCHAR(255) NOT NULL, ALGORITHM=INPLACE, LOCK=NONE;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE detection_exclusions MODIFY COLUMN rule_id VARCHAR(255) NOT NULL DEFAULT '', ALGORITHM=INPLACE, LOCK=NONE;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE detection_rule_match_counts MODIFY COLUMN rule_id VARCHAR(255) NOT NULL, ALGORITHM=INPLACE, LOCK=NONE;
-- +goose StatementEnd

-- +goose Down
-- Narrowing needs a full copy (rejected INPLACE, because it can lose data) and fails outright if any stored identifier exceeds 64
-- characters, which is the correct refusal rather than a truncation. The DEFAULT '' is carried back for the same reason it is
-- carried forward above.
-- +goose StatementBegin
ALTER TABLE detection_rule_match_counts MODIFY COLUMN rule_id VARCHAR(64) NOT NULL, ALGORITHM=COPY;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE detection_exclusions MODIFY COLUMN rule_id VARCHAR(64) NOT NULL DEFAULT '', ALGORITHM=COPY;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE detection_rule_settings MODIFY COLUMN rule_id VARCHAR(64) NOT NULL, ALGORITHM=COPY;
-- +goose StatementEnd
