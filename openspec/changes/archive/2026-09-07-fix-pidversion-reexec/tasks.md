# Tasks

## 1. Record the exec event's own generation

- [x] 1.1 Take `pidversion` from the exec event in `insertReExec` rather than from the generation being closed
- [x] 1.2 Delete `pickPIDVersion`, whose preference order was the defect: it took the prior value even when the event reported one
- [x] 1.3 Keep the replaced generation when the exec event reports none, matching what the agent's own registry keeps, so the pin survives

## 2. Correct the premise wherever it was recorded

- [x] 2.1 `execPayload.PIDVersion` doc: the exec target's generation never matches what the fork stored for that pid
- [x] 2.2 `ProcessExecUpdate.PIDVersion` doc: the exec's value differs from the fork's and is the one that must win through COALESCE
- [x] 2.3 `GetProcessByPIDVersion` doc and the `api.Service` interface doc: several generations sharing one identity is a legacy-row case, not kernel behavior
- [x] 2.4 The store test covering the shared-identity lookup: restate why the disambiguation is still required

## 3. Tests

- [x] 3.1 Table-driven regression for the in-place exec case (python3 spawning `zsh -c 'curl ...'`), including the no-pidversion arm
- [x] 3.2 Property test over fork / exec / re-exec / pid-reuse asserting every persisted generation carries the value its own event reported
- [x] 3.3 Confirm the property fails against the previous behavior, so it pins the fix rather than restating it
