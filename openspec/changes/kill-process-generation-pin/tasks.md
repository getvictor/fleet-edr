# Pin kill_process to the target process generation: tasks

## 1. Generation registry (agent)

- [x] `agent/procgen/procgen.go`: new per-agent `Registry` (concurrency-safe `pid -> pidversion`); `ObserveEventBytes` parses an exec/fork/exit envelope and updates the map (exec/fork set, exit clears); `Check(pid, expected)` returns Match / Mismatch / Unknown; nil-safe.

## 2. Receive-path feed (agent)

- [x] `agent/receiver/common.go`: add the `GenerationSink` interface plus `SetGenerationSink` / `getGenerationSink` (package-level, mirroring the logger seam).
- [x] `agent/receiver/receiver.go`: `onEvent` feeds the sink before `TryDeliverEvent`, so the map sees every delivered event regardless of upload-queue drops.

## 3. Executor gate (agent)

- [x] `agent/commander/executor.go`: `killPayload` gains optional `pidversion`; `Executor` gains a `gen *procgen.Registry` + `SetGeneration`; `runKill` refuses on `VerdictMismatch` (structured failure, no signal) and otherwise proceeds.
- [x] `agent/commander/commander.go` + `agent/controlclient/controlclient.go`: `Config.Generation` threads the shared registry to the executor on both transports.
- [x] `agent/cmd/fleet-edr-agent/main.go`: build one `procgen.Registry`, install it as the receiver sink before sensors start, and pass it to both command transports.

## 4. UI

- [x] `ui/src/components/ProcessDetail.tsx`: include `node.pidversion` in the kill_process payload when present; omit it (pid-only) when absent.

## 5. Spec

- [x] `agent-command-executor` delta: MODIFIED "Process-termination command" adds the generation-pin behavior and the refuse-on-mismatch / match-proceeds / fallback scenarios.

## 6. Tests

- [x] `agent/procgen/procgen_test.go`: table + property-based coverage of observe/forget/Check and `ObserveEventBytes` (exec/fork set, exit clears, missing pidversion and non-process events ignored, malformed JSON ignored).
- [x] `agent/commander/executor_generation_test.go`: runKill match kills, mismatch refuses (no signal, reason), unknown/absent/no-pidversion fall back, nil registry never refuses. Scenario markers on the gate subtests.
- [x] `agent/receiver/generation_sink_test.go`: `SetGenerationSink` / `getGenerationSink` round-trip and nil-safety.
- [x] `ui/src/components/ProcessDetail.test.tsx`: the kill payload includes `pidversion` when the node has one and omits it otherwise.
