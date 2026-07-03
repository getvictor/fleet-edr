//go:build windows

package etw

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	tdh                    = windows.NewLazySystemDLL("tdh.dll")
	procTdhGetProperty     = tdh.NewProc("TdhGetProperty")
	procTdhGetPropertySize = tdh.NewProc("TdhGetPropertySize")
)

// Record wraps a native EVENT_RECORD delivered to the consumer callback. It is only valid for the duration of the handler call (the
// pointer is OS-owned buffer memory); copy out any bytes you need before returning.
type Record struct {
	p *eventRecord
}

// EventID returns the manifest event id (for Kernel-Process: 1 = ProcessStart, 2 = ProcessStop).
func (r Record) EventID() uint16 { return r.p.EventHeader.EventDescriptor.ID }

// ProcessID returns the id of the process that logged the event (the EVENT_HEADER field, not a payload property).
func (r Record) ProcessID() uint32 { return r.p.EventHeader.ProcessID }

// GetProperty extracts a named top-level property from the event payload via TDH. It returns the raw little-endian bytes TDH writes,
// which the caller decodes per the property's type (uint32, FILETIME as int64, UTF-16 string, ...). An absent property or a decode
// failure returns an error carrying the TDH status.
func (r Record) GetProperty(name string) ([]byte, error) {
	nameU16, err := windows.UTF16FromString(name)
	if err != nil {
		return nil, err
	}
	desc := propertyDataDescriptor{PropertyName: uint64(uintptr(unsafe.Pointer(&nameU16[0]))), ArrayIndex: 0xFFFFFFFF}
	var size uint32
	r0, _, _ := procTdhGetPropertySize.Call(
		uintptr(unsafe.Pointer(r.p)), 0, 0, 1,
		uintptr(unsafe.Pointer(&desc)), uintptr(unsafe.Pointer(&size)),
	)
	if r0 != 0 {
		return nil, fmt.Errorf("etw: TdhGetPropertySize(%s): %w", name, windows.Errno(r0))
	}
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	r0, _, _ = procTdhGetProperty.Call(
		uintptr(unsafe.Pointer(r.p)), 0, 0, 1,
		uintptr(unsafe.Pointer(&desc)), uintptr(size), uintptr(unsafe.Pointer(&buf[0])),
	)
	// desc.PropertyName holds nameU16's address as a uint64, which the GC cannot trace; keep nameU16 alive until both TDH calls that
	// read it through desc have returned, or the slice could be collected mid-syscall.
	runtime.KeepAlive(nameU16)
	if r0 != 0 {
		return nil, fmt.Errorf("etw: TdhGetProperty(%s): %w", name, windows.Errno(r0))
	}
	return buf, nil
}

// Uint32 decodes a uint32 property (returns ok=false if absent or too short). TDH writes little-endian; decode via encoding/binary
// rather than an unsafe pointer cast so the read stays correct and alignment-safe on every architecture (notably ARM64).
func (r Record) Uint32(name string) (uint32, bool) {
	b, err := r.GetProperty(name)
	if err != nil || len(b) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b), true
}

// Int64 decodes an 8-byte property (FILETIME, ULONG64) as int64. As with Uint32, decode the little-endian bytes explicitly to avoid an
// unaligned unsafe cast that can panic or misread on ARM64.
func (r Record) Int64(name string) (int64, bool) {
	b, err := r.GetProperty(name)
	if err != nil || len(b) < 8 {
		return 0, false
	}
	return int64(binary.LittleEndian.Uint64(b)), true
}

// UTF16String decodes a UTF-16 string property to a Go string (empty if absent).
func (r Record) UTF16String(name string) string {
	b, err := r.GetProperty(name)
	if err != nil || len(b) < 2 {
		return ""
	}
	u16 := unsafe.Slice((*uint16)(unsafe.Pointer(&b[0])), len(b)/2)
	return windows.UTF16ToString(u16)
}
