# Tasks

- [x] Aggregate a batch's monitor matches per rule, host and severity while it evaluates, and hand the tally back rather than writing it.
- [x] Record the tally after the batch is acknowledged, so a replayed batch is counted once, and never fail the batch on a recording error.
- [x] Persist counts per (rule, host, day) in the rules context, with first-seen and last-seen.
- [x] Prune counts past the retention window from a ticker that holds no leader lock.
- [x] Correct the counter's non-deduplication caveat where it is stated, which this change supersedes.
