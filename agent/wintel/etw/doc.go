// Package etw is a minimal, pure-Go consumer of a real-time Event Tracing for Windows (ETW) session. It exists so the Windows agent
// sensor can subscribe to manifest providers (Microsoft-Windows-Kernel-Process to start) and read event properties without cgo and
// without a third-party ETW library: the maintained options are GPL-licensed or cgo-bound (ADR-0018), so the bindings are hand-rolled
// clean-room from the Microsoft ETW and TDH documentation.
//
// The syscall surface (StartTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, ControlTraceW, CloseTrace, and TdhGetProperty) plus the
// EVENT_RECORD callback via windows.NewCallback is implemented in the windows-tagged files of this package; there is no cross-platform
// build of the consumer itself. The event-to-envelope mapping that the sensor layers on top is kept out of this package (in the
// platform-neutral mapper) so it stays unit-testable off Windows.
package etw
