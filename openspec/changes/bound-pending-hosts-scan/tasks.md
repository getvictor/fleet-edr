# Tasks

- [x] Add migration `00003_event_queue_pending_hosts_index.sql` creating `(processed, timestamp_ns, claimed_at_ns, host_id)`.
- [x] Rewrite `PendingHosts` as one index-ordered arm per claim state, preserving the in-flight floor join unchanged.
- [x] Bound each arm with `PendingHostsScanWindow`, a fixed compiled constant.
- [x] Pin that the migration shipped, so the hint cannot silently revert to the full scan.
- [x] Pin both halves of the window trade: the oldest host is always offered, and a host beyond a full window is deferred and then served once the older work drains.
- [x] Measure before and after on a seeded 200k-row queue and confirm the host list is unchanged.
