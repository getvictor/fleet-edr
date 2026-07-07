## ADDED Requirements

### Requirement: Set-based batch materialization is equivalent to per-event application

The system SHALL materialize a batch using a bounded, small number of database round-trips that does not grow one-or-more per event: it MUST resolve the candidate process rows for the batch's `(host_id, pid)` set with a single bulk read, fold the batch against an in-memory model that reproduces the per-event resolution semantics (timestamp ordering, fork creation, exec-in-place update, exit closure, PID-reuse closure, exec-without-fork synthesis, same-PID re-exec chain linkage, snapshot dedup and freshness seeding, and the exit-before-snapshot-exec buffer), and persist the result with set-based writes. The resulting process forest MUST be identical to the forest produced by applying the same events one at a time in timestamp order, for any batch.

#### Scenario: Batched materialization equals per-event materialization

- **GIVEN** a batch of `fork`, `exec`, `exit`, and snapshot `exec` events, including same-PID re-exec sequences and PID reuse, applied to a host's current process forest
- **WHEN** the builder materializes the batch with its set-based path
- **THEN** the resulting process records (parent linkage, exec image and metadata, exit timestamps and reasons, re-exec chain back-references, snapshot markers and freshness timestamps) are identical to those produced by applying the same events individually in timestamp order

#### Scenario: A poison data error is isolated under batched persistence

- **GIVEN** a batch whose set-based write would fail because one row carries a value the database can never store (a permanent data-integrity violation) alongside otherwise-valid rows
- **WHEN** the builder flushes the batch
- **THEN** the offending row is dropped and logged, the remaining rows are materialized, and the batch is reported successful so the processor marks it processed and does not retry it
- **AND** a transient (retryable) write fault instead fails the whole batch so the processor retries it and no data is lost
