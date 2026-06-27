-- +goose Up
-- ADR-0015 cutover: the event store moves to ClickHouse, so the MySQL `events` table is dropped. Ingestion now fans out to the
-- ClickHouse archive plus the visibility event_queue, the processor claims from that queue, and per-process correlation + self-contained
-- alert evidence read the archive. `alert_events` keeps the correlated event_id set (the alert-detail event_ids) but its event_id no
-- longer references a MySQL row, so its foreign key to events is dropped first; the table itself is then removed.
--
-- This is a forward-only, irreversible data migration. Production rollback is restore-from-backup (ADR-0009), consistent with the other
-- schema-rewrite migrations in this corpus.

-- +goose StatementBegin
ALTER TABLE alert_events DROP FOREIGN KEY fk_ae_event;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE events;
-- +goose StatementEnd

-- +goose Down
-- Forward-only: the events table held telemetry that now lives in ClickHouse (the source of truth post-cutover), so there is no lossless
-- way to reconstruct it here. Rollback is restore-from-backup (ADR-0009). The no-op keeps goose's Down section well-formed.

-- +goose StatementBegin
SELECT 1;
-- +goose StatementEnd
