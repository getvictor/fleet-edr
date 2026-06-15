# Fix process uid/gid overflow: tasks

## 1. Schema

- [x] Migration `00003_processes_uid_unsigned.sql`: `ALTER TABLE processes MODIFY uid INT UNSIGNED, MODIFY gid INT UNSIGNED` (goose up/down).

## 2. Pipeline resilience

- [x] `internal/mysql/errors.go`: `IsPermanentDataError` classifying MySQL data-integrity error numbers (1264, 1265, 1292, 1366, 1406, 3819); unknown errors treated as transient.
- [x] `internal/graph/builder.go` `ProcessBatch`: drop events that fail with a permanent error (log `event dropped: permanent processing error`); fail the batch only for transient errors so the processor retries them.

## 3. Spec

- [x] `server-process-graph-builder`: ADDED "Process records store the full macOS uid and gid range" and "A single unpersistable event does not stall batch processing".

## 4. Tests

- [x] `internal/mysql/errors_test.go`: table-driven `IsPermanentDataError` (permanent vs transient vs wrapped vs non-mysql vs nil), with the transient-retry scenario marker.
- [x] Integration (`internal/tests`, real MySQL): a `nobody` exec (uid 4294967294 / gid 4294967295) persists; a poison event (over-long host_id) is dropped while the valid event in the batch is materialized and the batch reports success.

## 5. Verification

- [ ] `go build ./server/...`; `go test ./server/detection/internal/mysql/...`; `go test -tags integration ./server/detection/internal/tests/...` (needs `EDR_TEST_DSN`).
- [ ] gofmt, golangci-lint, `openspec validate fix-process-uid-gid-overflow --strict`, spectrace.
