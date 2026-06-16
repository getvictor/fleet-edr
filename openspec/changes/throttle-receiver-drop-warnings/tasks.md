# Throttle the receiver's dropped-event warnings: tasks

## 1. Receiver

- [x] `agent/receiver/common.go`: add `dropReporter` (`pending` count + `lastEmit` time, `now` clock seam) and `dropWarnInterval` (5s). `record` returns the count to log now (this drop plus suppressed drops since the last warning) or 0 when suppressed. `tryDeliverEvent` takes a `*dropReporter` and only logs when `record` returns emit=true, adding a `dropped` count attribute to the warning.
- [x] `agent/receiver/receiver.go`: each `Receiver` owns its `drops *dropReporter` (created in `New`, passed from `onEvent`). No package-level global and no per-service map: one Mach service per receiver, so the reporter is a single counter, which also removes cross-receiver lock contention on the drop path and gives clean test isolation.

## 2. Spec

- [x] `agent-xpc-receiver` spec: MODIFIED requirement "Events flow into the queue without blocking the receiver" so the warning is rate-limited and carries a dropped-event count; kept the "Downstream consumer falls behind" scenario and added "Sustained drops are coalesced into a throttled summary".

## 3. Tests

- [x] `agent/receiver/common_test.go`: existing drop test uses a fresh per-receiver reporter and asserts `dropped=1`. New `TestDropReporter_CoalescesSustainedDrops` drives a 1000-drop burst through a fake clock: first drop warns (count 1), the next 999 are suppressed, crossing `dropWarnInterval` emits one summary (count 1000), and a second reporter warns on its own first drop (independent windows). Scenario marker on the new test.

## 4. Verification

- [x] `go test ./agent/receiver/` green.
- [ ] gofmt + `task lint:go` on the touched package; `openspec validate throttle-receiver-drop-warnings --strict`; `tools/spectrace`; dash + markdown lints.
