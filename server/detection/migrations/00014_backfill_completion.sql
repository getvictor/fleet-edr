-- +goose Up
-- Record that a one-shot backfill finished, so it runs once per deployment rather than once per boot per replica (#872).
--
-- The alert-origin backfill (#870) is leader-gated, and a leader lock is the wrong tool for "once ever": DoOnceIfLeader releases
-- the lock when its callback returns, so it excludes OVERLAPPING callers, not repeated ones. Replicas in a rolling restart start
-- in turn, so each one acquires the lock in turn and each runs the full pass.
--
-- The pass is a table scan of alerts, and it stays one: there is no index on origin, and rule_id sits third in the dedup key
-- behind source and host_id. Indexing rule_id would help and would tax every alert INSERT on the hot detection path for the life
-- of the deployment, to save a scan on a leader-only boot path. Durable completion is the cheaper side of that trade, and it makes
-- the already-credited boot free rather than merely cheaper.
--
-- Keyed by NAME rather than a boolean column on a singleton row, because the alternative is an ALTER per backfill and there is
-- already a second one in view: #871 widens attribution to alerts from rules no longer in the corpus, which is a different pass
-- over a different population and completes independently of this one.

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS detection_backfills (
	name         VARCHAR(64)  NOT NULL PRIMARY KEY,
	completed_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;
-- +goose StatementEnd

-- +goose Down
-- Forward-only migrations (ADR-0009). Dropping this would make every recorded backfill run again on the next boot, which is a
-- scan per replica rather than a correctness problem, but re-applying would still silently undo the fix. The rollback path is
-- restore-from-backup.
