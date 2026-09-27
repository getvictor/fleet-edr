//go:build darwin && cgo

package procpath

/*
#include <libproc.h>
*/
import "C"

import "unsafe"

// Path returns the executable path of the running process pid, or ("", false) when there is no such process.
func Path(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	buf := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
	n := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if n <= 0 {
		return "", false
	}
	return string(buf[:n]), true
}
