# Tasks: select the re-exec generation by event time within a matching pidversion

## 1. Store lookup

- [x] `GetProcessByPIDVersion` takes an `atNs` anchor and selects, within the matching `(host_id, pid, pidversion)` set, the generation that was the running image at `atNs` (`COALESCE(exec_time_ns, fork_time_ns) <= atNs` and not yet exited), falling back to the live/newest generation when none brackets. A single match stays timestamp-independent.
- [x] Update the `GraphReader` interface signature and doc in `server/detection/api/service.go`.

## 2. Caller

- [x] `resolveFlowProcess` forwards the flow's `atNs` to `GetProcessByPIDVersion`; the identity-miss and no-pidversion paths still fall back to `GetProcessByPID`.

## 3. Tests

- [x] Real-MySQL `GetProcessByPIDVersion`: a re-exec chain sharing one `pidversion` resolves a flow during the earlier generation to that generation, and a flow during the later generation to the later one.
- [x] A single-match (PID reuse) lookup stays timestamp-independent (resolves by identity even when `atNs` falls outside the generation's window).
- [x] Update the rule-level `GraphReader` fakes for the new signature; `resolveFlowProcess` precedence tests still pass.

## 4. Spec + gates

- [x] Modify the "Network and DNS events are linked to the process at event time" requirement with the within-identity timestamp-selection rule and a re-exec scenario.
- [x] `openspec validate --all --strict`, `go build`, `go test` (real MySQL), `spectrace`.
