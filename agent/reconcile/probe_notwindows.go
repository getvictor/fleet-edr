//go:build !windows

package reconcile

import "syscall"

// defaultKill is the liveness probe on Unix-like platforms: syscall.Kill, which the reconciler calls with signal 0 to test whether a pid
// exists (nil or EPERM mean alive, ESRCH means gone). Split behind a build tag because syscall.Kill does not exist on Windows, which
// emulates the same three-way result via OpenProcess (probe_windows.go).
var defaultKill KillFunc = syscall.Kill
