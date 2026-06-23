# Keep good telemetry queued on blanket endpoint rejection: tasks

## 1. Uploader

- [ ] `agent/uploader/uploader.go`: add `endpointRejectedError{statusCode}`. In `doUpload`, classify 401 and 400 as `clientError` (re-enroll / quarantine paths unchanged), 413 as `requestEntityTooLargeError`, and every other 4xx as `endpointRejectedError`. `uploadWithRetry` returns `endpointRejectedError` immediately (non-retryable within the cycle, like the other 4xx). `handleUploadErr` routes `endpointRejectedError` to a WARN (`audit=uploader.endpoint_rejecting`, `status_code`) plus the new counter and keeps the batch queued; the quarantine branch now only ever sees 400.

## 2. Metrics

- [ ] `agent/metrics/metrics.go`: add the `edr.agent.uploader.endpoint_rejected` counter (labelled by `status_code`) and the `UploadRejected(ctx, statusCode)` method; add `UploadRejected` to the uploader's `MetricsRecorder` interface. Nil-safe.

## 3. Spec

- [ ] `agent-event-uploader` delta: MODIFY "Permanent client errors are not infinitely retained" to scope quarantine to HTTP 400; ADD "Blanket endpoint rejections keep the queue" with the sustained-403 / resume-on-2xx and the non-400-4xx scenarios.

## 4. Tests

- [ ] `agent/uploader/uploader_test.go`: sustained 403 keeps the queue and resumes on 200; a persistent 400 still quarantines while a sibling batch delivers; 404/429 are kept queued. Extend `fakeMetrics` with `UploadRejected`. Scenario markers on the new tests; update the renamed 400-quarantine marker.

## 5. Verification

- [ ] `go test ./agent/...` green; gofmt + `task lint:go` on touched packages; `openspec validate uploader-edge-rejection-no-quarantine --strict`; `tools/spectrace`; dash + markdown lints.
- [ ] Manual E2E: agent against the dev server, inject a sustained 403 at an edge shim, confirm the queue is preserved + `edr.agent.uploader.endpoint_rejected` shows in SigNoz + no drop; restore 200 and confirm the backlog drains.
