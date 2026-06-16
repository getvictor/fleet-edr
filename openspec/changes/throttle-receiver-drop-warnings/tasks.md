# Throttle the receiver's dropped-event warnings: tasks

## 1. Receiver

- [x] `agent/receiver/common.go`: add `dropReporter` (per-service `pending` count + `lastEmit` time, `now` clock seam) and `dropWarnInterval` (5s). `record` returns the count to log now (this drop plus suppressed drops since the last warning) or 0 when suppressed. `tryDeliverEvent` calls `drops.record` and only logs when it returns emit=true, adding a `dropped` count attribute to the warning.

## 2. Spec

- [x] `agent-xpc-receiver` spec: MODIFIED requirement "Events flow into the queue without blocking the receiver" so the warning is rate-limited and carries a dropped-event count; kept the "Downstream consumer falls behind" scenario and added "Sustained drops are coalesced into a throttled summary".

## 3. Tests

- [x] `agent/receiver/common_test.go`: existing drop test resets the shared reporter and asserts `dropped=1`. New `TestDropReporter_CoalescesSustainedDrops` drives a 1000-drop burst through a fake clock: first drop warns (count 1), the next 999 are suppressed, crossing `dropWarnInterval` emits one summary (count 1000), and a distinct service warns on its own first drop. Scenario marker on the new test.

## 4. Verification

- [x] `go test ./agent/receiver/` green.
- [ ] gofmt + `task lint:go` on the touched package; `openspec validate throttle-receiver-drop-warnings --strict`; `tools/spectrace`; dash + markdown lints.
