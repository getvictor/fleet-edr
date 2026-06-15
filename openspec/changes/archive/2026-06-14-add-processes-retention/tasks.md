# Processes retention window: tasks

## 1. Runner

- [x] `retention.go`: add a batched processes DELETE to `Run` keyed on `exit_time_ns < cutoff`, completed rows only, with the `NOT EXISTS` alerts FK guard; factor a `pruneBatched` helper shared with the event delete.
- [x] `retention.go`: update the `RetentionRunner` doc comment to describe both row families and the exit-time-not-fork-time rationale.

## 2. Schema

- [x] Migration `00002_processes_retention_index.sql`: `idx_processes_exit_time (exit_time_ns)` (goose up/down).

## 3. Observability

- [x] `detection/api` `MetricsRecorder`: add `ProcessRetentionRowsDeleted`.
- [x] `metrics.go`: `edr.retention.processes.rows_deleted` counter + method.
- [x] `retention.go`: emit the new metric + `edr.retention.processes.rows_deleted` span attribute.

## 4. Spec

- [x] `server-process-graph-builder` spec: ADDED requirement "Completed process records are pruned after the retention window" with three scenarios.

## 5. Tests

- [x] Integration test (`TestRetention_PrunesCompletedProcesses`, real MySQL): old-completed pruned; recent-completed, live-snapshot, live-non-snapshot, and alert-referenced all retained; metric counts one. Scenario markers on the test.

## 6. Verification

- [ ] `go build ./server/...`; `go test -tags integration ./server/detection/internal/tests/...` green.
- [ ] `go test ./server/metrics/...` green.
- [ ] gofmt, golangci-lint, spectrace, markdown + dash lints, `openspec validate add-processes-retention`.
