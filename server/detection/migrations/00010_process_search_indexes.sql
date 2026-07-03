-- +goose Up
-- Indexes for the fleet-wide process search (issue #582). The existing processes indexes are all host-scoped or single-column, so a
-- cross-host query ordered by fork_time_ns or filtered by hash would table-scan. idx_processes_fork_id is the keyset sort key
-- (fork_time_ns, id) DESC-paged by the search; idx_processes_sha256 backs the "all execs of this hash" pivot, the search's most
-- common fleet-wide entry. Path/uid/exit_reason apply as residual predicates on the scanned rows (no per-filter index until a real
-- query mix justifies one).
CREATE INDEX idx_processes_fork_id ON processes (fork_time_ns, id);
CREATE INDEX idx_processes_sha256 ON processes (sha256);

-- +goose Down
DROP INDEX idx_processes_fork_id ON processes;
DROP INDEX idx_processes_sha256 ON processes;
