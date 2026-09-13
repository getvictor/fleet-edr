-- +goose Up
-- Index backing the host page's read of a host's recorded sensor faults (issue #778). The detection context reads, per host, the newest
-- open faults and the most recently resolved ones:
--   ... WHERE host_id = ? AND resolved_at_ns IS NULL     ORDER BY opened_at_ns   DESC LIMIT ?
--   ... WHERE host_id = ? AND resolved_at_ns IS NOT NULL ORDER BY resolved_at_ns DESC LIMIT ?
-- The table's first indexes serve neither well. Measured with EXPLAIN on 3,000 hosts holding 31 faults each: the open half walked
-- (host_id, opened_at_ns) newest first and discarded resolved rows as it went, so an old fault still open beneath a long resolved history
-- reads that whole history. The resolved half took the component index and filesorted every resolved fault the host has, and those
-- accumulate for the life of the host. The LIMIT bounded the rows returned, not the work done to find them.
--
-- (host_id, resolved_at_ns, opened_at_ns) serves both: an equality on host_id, then the NULL / NOT NULL split on resolved_at_ns, then an
-- index-ordered read of whichever timestamp that half sorts on. On a host with 20,000 recorded faults both halves became backward,
-- index-only scans that stop at the LIMIT. On a host with a short history the optimizer may still prefer a filesort over its few dozen
-- rows, which costs about the same.
--
-- A secondary-index add, so it is built online and ships single-step under ADR-0009. No down section, per the same ADR.

-- +goose StatementBegin
CREATE INDEX idx_host_health_episodes_host_read ON host_health_episodes (host_id, resolved_at_ns, opened_at_ns);
-- +goose StatementEnd
