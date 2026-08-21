-- +goose Up
-- Back the candidate-host hint with an index it can actually read, instead of a full scan of the queue (issue #720).
--
-- PendingHosts answers "which hosts have claimable work, oldest first". Its predicate ORs across the two claim states (never-claimed,
-- and claim-expired), which defeats idx_event_queue_claim (processed, host_id, timestamp_ns): that index is ordered by host within a
-- claim state, so a query wanting global timestamp order across states has to read every row and sort. Measured on a seeded 200k-row
-- queue across 200 hosts, the shipped hint costs 67.6ms as a full scan plus a temp-table aggregate, and the cost grows with backlog
-- depth, so it is worst exactly when the pipeline is behind. At the 500ms poll interval with 4 workers that is roughly 8 such scans a
-- second.
--
-- (processed, timestamp_ns, claimed_at_ns, host_id) serves all three reads the rewritten hint makes, and is covering for each:
--   * the never-claimed arm      -> range on processed = 0, already in timestamp order, no sort
--   * the claim-expired arm      -> range on processed = 2, claimed_at_ns filtered in-index while scanning in timestamp order
--   * the per-host in-flight floor -> range on processed = 2, grouped by host_id from the index
-- Measured with this index: 3.3ms, a 20x improvement, and better than the two separate indexes an earlier candidate used
-- ((processed, timestamp_ns) plus (processed, claimed_at_ns, host_id, timestamp_ns)) at 5.3ms.
--
-- ONE index rather than two is deliberate. event_queue is the ingest hot path and every index is maintained on insert, so the write
-- cost of the fix should stay at one B-tree. It does not replace idx_event_queue_claim, which is still what the per-host claim itself
-- reads (host_id is the leading discriminator there, and it is the ordering the FOR UPDATE SKIP LOCKED scan depends on).

-- +goose StatementBegin
ALTER TABLE event_queue ADD INDEX idx_event_queue_pending (processed, timestamp_ns, claimed_at_ns, host_id);
-- +goose StatementEnd

-- +goose Down
ALTER TABLE event_queue DROP INDEX idx_event_queue_pending;
