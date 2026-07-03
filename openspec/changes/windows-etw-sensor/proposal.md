## Why

The Windows agent (ADR-0018) can enroll and run commands but produces no telemetry: on Windows the receiver is the non-darwin stub. This change gives it its first real sensor, a driverless user-mode consumer of the Microsoft-Windows-Kernel-Process ETW provider, so a Windows host reports process start/stop events into the same pipeline macOS uses. Driverless (no ELAM/PPL, no MVI) is the deliberate Phase 1 choice; the deeper kernel tier stays a future, contingent phase.

The ETW bindings are hand-rolled in pure Go: the maintained third-party ETW libraries are GPL-licensed or cgo-bound, both non-starters here (the agent builds CGO_ENABLED=0). The approach was validated end-to-end on a Windows 11 25H2 host before productizing: real-time session consumption via `windows.NewCallback`, TDH property extraction, QueryDosDevice path conversion, and the full envelope mapping all confirmed against live process events.

## What changes

- Add `agent/wintel/etw`: a minimal pure-Go ETW consumer (StartTraceW / EnableTraceEx2 / OpenTraceW / ProcessTrace / ControlTraceW / CloseTrace + an EVENT_RECORD callback, and TdhGetProperty for payload extraction).
- Add `agent/wintel`: a `receiver.Connector` sensor that consumes Kernel-Process, maps ProcessStart to an `exec` envelope and ProcessStop to an `exit` envelope stamped `platform: "windows"`, converts the NT device image path to a DOS path, and carries the process create time as `create_time_ns` (the platform-neutral pid_epoch of ADR-0018, the Windows analogue of macOS pid_version).
- Wire the sensor into the agent: a platform sensor seam (`sensors_windows.go` / `sensors_notwindows.go`) runs the Windows ETW sensor loop, or the macOS ESF + network-extension loops, through the shared receiver.Loop (reconnect/backoff/heartbeat + health). A new health component `windows_etw_sensor` reports its state.
- Extend `schema/events.json`: an optional `create_time_ns` on the exec and exit payloads.

Out of scope, tracked as follow-ups: process command-line capture (needs a PEB read or Security-4688 correlation; args ship empty for now), Authenticode signing, network/DNS ETW providers, and the privileged ELAM/PPL tier.

## Capabilities

### Added capabilities

- `windows-event-collection`: the Windows agent consumes the Kernel-Process ETW provider and emits exec/exit event envelopes tagged with the windows platform, the process create time (pid_epoch), and a DOS image path.

## Impact

- Code (agent): new `agent/wintel/etw` (windows-tagged ETW/TDH bindings) and `agent/wintel` (the sensor plus a platform-neutral mapper); a platform sensor seam in `agent/cmd/fleet-edr-agent` (`sensors.go`, `sensors_notwindows.go`, `sensors_windows.go`) replacing the inline macOS block in `main.go`; a `connectorFactory` hook on the receiver loop; a `windows_etw_sensor` health component.
- Schema: an optional `create_time_ns` on exec and exit payloads (openspec-sync gated path, so this delta ships with it).
- Coverage: the windows-tagged sensor/bindings run on no CI runner (there is no Windows CI yet), so they stay under the `**/*_windows.go` Sonar coverage exclusion from ADR-0018; the platform-neutral mapper is unit-tested on the macOS/Linux runners, and the live ETW path is validated on a Windows dev VM (an `agent/wintel/etw` live smoke test plus a sensor end-to-end run).
- No server, wire-contract, or macOS behavior change: the envelope gains an optional field, and macOS still emits pid_version, not create_time_ns.
