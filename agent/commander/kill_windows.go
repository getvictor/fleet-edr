//go:build windows

package commander

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// defaultKill terminates the process with the given pid. Windows has no POSIX signals; TerminateProcess is the SIGKILL equivalent, so the
// signal argument is ignored (runKill only ever passes SIGKILL). The OpenProcess and TerminateProcess errors are returned unchanged so
// the command outcome carries the real failure reason. Exit code 1 is conventional for a force-terminated process.
func defaultKill(pid int, _ syscall.Signal) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	return windows.TerminateProcess(h, 1)
}
