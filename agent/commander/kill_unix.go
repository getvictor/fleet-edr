//go:build !windows

package commander

import "syscall"

// defaultKill is the process-termination primitive on Unix-like platforms: syscall.Kill, invoked with SIGKILL by runKill. Split behind a
// build tag because syscall.Kill does not exist on Windows, which uses TerminateProcess instead (kill_windows.go).
var defaultKill = syscall.Kill
