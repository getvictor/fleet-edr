//go:build windows

package reconcile

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// stillActive is Windows' STILL_ACTIVE (259): GetExitCodeProcess returns it for a process that has not yet exited. A process that
// genuinely exits with code 259 is indistinguishable here, but that is a negligible corner for a liveness probe.
const stillActive = 259

// defaultKill is the Windows liveness probe. The reconciler only ever calls it with signal 0 (a pure existence check), so the signal is
// ignored. It maps process existence onto the same POSIX errnos the pass classifier in runPass expects, keeping that ESRCH/EPERM/nil
// switch byte-identical across platforms:
//
//   - nil: the pid exists and is running (OpenProcess succeeded and the exit code is STILL_ACTIVE).
//   - syscall.EPERM: the pid exists but is not queryable (access denied), which is positive proof of liveness, mirroring Unix EPERM.
//   - syscall.ESRCH: the pid is gone (OpenProcess failed with an invalid parameter, or the handle opened but the process had exited).
func defaultKill(pid int, _ syscall.Signal) error {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return syscall.EPERM
		}
		return syscall.ESRCH
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		// The handle is valid, so the process exists; we just cannot read its exit code. Treat as alive, like EPERM.
		return syscall.EPERM
	}
	if code == stillActive {
		return nil
	}
	// The handle pinned a pid whose process has already exited. Report it gone so the reconciler synthesizes the missing exit.
	return syscall.ESRCH
}
