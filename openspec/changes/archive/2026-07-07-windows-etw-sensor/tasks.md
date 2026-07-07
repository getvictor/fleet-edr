# Tasks

## ETW bindings

- [x] `agent/wintel/etw`: pure-Go session (StartTraceW/EnableTraceEx2/ControlTraceW), consumer (OpenTraceW/ProcessTrace/CloseTrace + EVENT_RECORD callback), and TDH property extraction.
- [x] Live smoke test on a Windows dev VM (real-time Kernel-Process consumption + field extraction).

## Sensor

- [x] `agent/wintel` mapper (platform-neutral, unit-tested): FILETIME->Unix ns, NT->DOS path, exec/exit envelope construction with `platform: windows` and `create_time_ns`.
- [x] `agent/wintel` sensor implementing `receiver.Connector`: consume Kernel-Process, map ProcessStart->exec / ProcessStop->exit, build the QueryDosDevice device map.
- [x] Validate the full sensor end-to-end on the Windows dev VM (exec/exit envelopes with correct ppid, DOS path, create_time_ns pairing, exit_code).

## Wiring

- [x] Platform sensor seam (`sensors.go` / `sensors_notwindows.go` / `sensors_windows.go`) + `connectorFactory` on the receiver loop.
- [x] `windows_etw_sensor` health component.
- [x] Optional `create_time_ns` on exec and exit payloads in `schema/events.json`.

## Follow-ups

- [ ] Process command-line capture (PEB read or Security-4688 correlation).
- [ ] Authenticode signing, network/DNS ETW providers, privileged ELAM/PPL tier.
- [ ] A Windows CI runner so the sensor/bindings get coverage instead of the exclusion.
