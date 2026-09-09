# Tasks

## 1. Queue contract

- [x] 1.1 Add `NackResult` to the visibility API and give `Nack` a `tally []byte` parameter, documenting that the queue keeps the bytes without interpreting them and returns them only on a full withdrawal.
- [x] 1.2 Add the nullable `monitor_tally` `BLOB` column to `event_queue` in a forward-only migration, opaque rather than `JSON` so the bytes come back as they went in.
- [x] 1.3 Store the tally on one deterministically chosen row inside the nack's existing `UPDATE`, only when the caller supplied one, and read it back only for a whole withdrawal.

## 2. Detection pipeline

- [x] 2.1 Add a versioned wire shape for the tally, so renaming a field of the API type cannot silently change what a previous version persisted.
- [x] 2.2 Hand the tally to `Nack` on the detection-failure path, and log an encoding failure without failing the nack.
- [x] 2.3 Record the carried tally on the fold-failure path when the whole batch is withdrawn.

## 3. Tests

- [x] 3.1 Store-level integration tests: the value survives the attempt that supplied it, a nack with none does not clear it, nothing is returned for a batch that is coming back or partly withdrawn, and a later value replaces the one it supersedes.
- [x] 3.2 Pipeline test replacing the residual subtest: a fold-stage withdrawal records what the evaluating attempt matched.
- [x] 3.3 Round-trip and failure tests for the codec.
- [x] 3.4 Mutation-test each new guard.

## 4. Spec

- [x] 4.1 Replace the residual paragraph and its scenario in `observability-instrumentation`.
- [x] 4.2 Add the queue carry requirement to `server-event-ingestion`.
- [x] 4.3 Move the spectrace markers to the tests that now carry the scenarios.
