-- +goose Up
-- Index backing the processes retention prune (issue #360). The retention runner deletes completed process rows whose exit_time_ns is
-- older than the retention cutoff:
--   DELETE FROM processes WHERE exit_time_ns IS NOT NULL AND exit_time_ns < ? AND NOT EXISTS (...) ORDER BY exit_time_ns LIMIT ?
-- Without this index that ordered range delete is a full scan plus filesort of the processes table on every batch. The index turns it
-- into a bounded range scan, mirroring idx_events_timestamp for the event retention delete. Live rows carry exit_time_ns IS NULL, which
-- a B-tree index groups at one end, so the prune's range scan also skips the live working set cheaply.

-- +goose StatementBegin
CREATE INDEX idx_processes_exit_time ON processes (exit_time_ns);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX idx_processes_exit_time ON processes;
-- +goose StatementEnd
