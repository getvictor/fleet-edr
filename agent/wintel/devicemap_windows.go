//go:build windows

package wintel

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procQueryDosDeviceW  = kernel32.NewProc("QueryDosDeviceW")
	procGetLogicalDrives = kernel32.NewProc("GetLogicalDrives")
)

// buildDeviceMap maps each mounted volume's NT device path to its DOS drive (e.g. \Device\HarddiskVolume4 -> C:) so ntPathToDOS can
// rewrite the NT image paths ETW reports into familiar DOS paths. Built once per Connect: the mapping is stable for a session, and a
// volume mounted mid-session simply falls back to the raw NT path (ntPathToDOS leaves unmatched paths unchanged). Best-effort: a drive
// that fails to resolve is skipped rather than failing the sensor.
func buildDeviceMap() map[string]string {
	m := make(map[string]string)
	mask, _, _ := procGetLogicalDrives.Call()
	buf := make([]uint16, 1024)
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		drive := string(rune('A'+i)) + ":" // e.g. "C:"
		driveU16, err := windows.UTF16FromString(drive)
		if err != nil {
			continue
		}
		n, _, _ := procQueryDosDeviceW.Call(
			uintptr(unsafe.Pointer(&driveU16[0])),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
		)
		if n == 0 {
			continue
		}
		target := windows.UTF16ToString(buf)
		if target != "" {
			m[target] = drive
		}
	}
	return m
}
