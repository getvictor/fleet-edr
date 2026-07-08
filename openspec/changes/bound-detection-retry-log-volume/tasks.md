# Bound detection retry log volume: tasks

## 1. Metric surface

- [x] `server/detection/api/service.go`: add `DetectionMaterializationRetry(ctx)` to the `MetricsRecorder` interface.
- [x] `server/metrics/metrics.go`: register the `edr.detection.materialization_retries` Int64Counter (unit `{retry}`) and implement the nil-safe `DetectionMaterializationRetry` method.

## 2. Processor

- [x] `server/detection/internal/pipeline/processor.go`: accept the builder and evaluator through local `batchBuilder` / `batchEvaluator` interfaces; add a `metrics` field and `SetMetrics`; route a detection failure through `logDetectionRetry`, which counts + debug-logs a not-yet-materialized miss (`rulesapi.ErrProcessNotYetMaterialized`) and keeps warn for any other failure.
- [x] `server/detection/internal/pipeline/runner.go`: propagate the recorder to the processor in `SetMetrics`.

## 3. Spec

- [x] `observability-instrumentation` delta: MODIFIED "Stable counter names" adds `edr.detection.materialization_retries` and its scenario; ADDED "Detection materialization-miss retries are bounded in log volume" with the debug-vs-warn scenarios.

## 4. Tests

- [x] `server/detection/internal/pipeline/processor_test.go`: drive `ProcessOnce` with fakes; a materialization miss debug-logs + increments the counter + nacks, a genuine failure warn-logs + does not count, a builder failure warn-logs, the happy path acks, and an unset recorder does not panic. Scenario markers on the miss/genuine subtests.
- [x] `server/detection/internal/pipeline/queueprune_test.go`: `capturingRecorder` implements the new method.
- [x] `server/metrics/metrics_test.go`: `TestRecorder_RecordsCounters` fires and asserts `edr.detection.materialization_retries`. Scenario marker for the stable-counter scenario.

## 5. Verification

- [ ] `go build ./server/...`, `go vet -tags integration ./server/detection/...`, `go test ./server/detection/... ./server/metrics/...` green.
- [ ] `openspec validate bound-detection-retry-log-volume --strict`; spectrace; `task lint:go`; dash + markdown lints.
