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
-- (processed, timestamp_ns, claimed_at_ns, host_id) serves the rewritten hint's three reads, each on a single `processed` value:
--   * the never-claimed arm        -> range on processed = 0, per-host MIN taken from the index
--   * the claim-expired arm        -> range on processed = 2, then claimed_at_ns evaluated from index data
--   * the per-host in-flight floor -> range on processed = 2, then claimed_at_ns evaluated from index data
--
-- Worth being precise about the second and third, because the loose phrasing invites a wrong conclusion in future performance work
-- (Qodo caught it on review). `processed` is the only column pruning the range: claimed_at_ns sits after timestamp_ns in the key, so
-- with timestamp_ns unconstrained it cannot narrow the scan. What the index buys those two arms is that claimed_at_ns and host_id
-- are both present, so the predicate and the grouping are answered without touching the table. They still walk every processed = 2
-- entry, which is fine because that set is bounded by in-flight plus recently-expired claims rather than by the backlog.
-- Measured with it: 29.8ms against 67.6ms shipped. Splitting the OR into two arms is most of that (67.6 to 37) and this index the
-- rest (37 to 29.8).
--
-- ONE index rather than two is deliberate. event_queue is the ingest hot path and every index is maintained on insert, so the write
-- cost of the fix should stay at one B-tree. It does not replace idx_event_queue_claim, which is still what the per-host claim itself
-- reads (host_id is the leading discriminator there, and it is the ordering the FOR UPDATE SKIP LOCKED scan depends on).

-- +goose StatementBegin
ALTER TABLE event_queue ADD INDEX idx_event_queue_pending (processed, timestamp_ns, claimed_at_ns, host_id);
-- +goose StatementEnd

-- +goose Down
ALTER TABLE event_queue DROP INDEX idx_event_queue_pending;
