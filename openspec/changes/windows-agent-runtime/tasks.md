# Tasks

## Compile seams

- [x] Kill seam in `agent/commander` (`kill_unix.go` = syscall.Kill, `kill_windows.go` = OpenProcess + TerminateProcess).
- [x] Liveness-probe seam in `agent/reconcile` (`probe_notwindows.go` = syscall.Kill, `probe_windows.go` = OpenProcess existence check mapping to ESRCH/EPERM/nil).
- [x] Host-id split in `agent/hostid` (darwin ioreg, windows MachineGuid, other returns an error) with the package doc in `doc.go`.
- [x] Platform default paths in `agent/config` (darwin/linux Unix paths, windows ProgramData).

## Build and CI

- [x] Promote `golang.org/x/sys` to a direct dependency.
- [x] `build:agent:windows` Taskfile target (amd64 + arm64 build and vet).
- [x] Wire `build:agent:windows` into the agent-test CI job.
- [x] Exclude `**/*_windows.go` and `**/*_other.go` from Sonar coverage.

## Tests

- [x] Config test asserts the platform-appropriate default paths on the current platform.
- [x] Existing commander process-termination tests continue to cover the (now platform-native) kill scenarios on the Unix runner.

## Follow-ups (require a Windows environment)

- [ ] Windows service wrapper (`svc.Run`) and MSI `ServiceInstall`.
- [ ] A windows-latest CI job running the agent unit tests with coverage.
- [ ] Authenticode verification and the ETW telemetry sensor.
