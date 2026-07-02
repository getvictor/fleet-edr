//go:build windows

package etw

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32           = windows.NewLazySystemDLL("advapi32.dll")
	procStartTraceW    = advapi32.NewProc("StartTraceW")
	procEnableTraceEx2 = advapi32.NewProc("EnableTraceEx2")
	procControlTraceW  = advapi32.NewProc("ControlTraceW")
)

// Session is a real-time ETW trace session. Start one, enable one or more providers on it, then open a Consumer against its name to
// read events. Stop releases the kernel session; a leaked session survives process exit, so callers must Stop on shutdown.
type Session struct {
	handle uint64
	name   []uint16 // UTF-16, NUL-terminated
}

// StartSession creates (or reclaims) a real-time session with the given name. If a session with the name already exists (for example
// leaked by a previous crashed run), it is stopped first so the create succeeds. The name should be stable per agent so a restart
// reclaims rather than accumulates sessions.
func StartSession(name string) (*Session, error) {
	nameU16, err := windows.UTF16FromString(name)
	if err != nil {
		return nil, fmt.Errorf("etw: encode session name: %w", err)
	}
	stopByName(nameU16) // best-effort reclaim of a leaked session

	buf := make([]byte, int(unsafe.Sizeof(eventTraceProperties{}))+len(nameU16)*2)
	props := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
	props.Wnode.BufferSize = uint32(len(buf))
	props.Wnode.Flags = wnodeFlagTracedGUID
	props.Wnode.ClientContext = clientContextQPC
	props.LogFileMode = eventTraceRealTimeMode
	props.LoggerNameOffset = uint32(unsafe.Sizeof(eventTraceProperties{}))

	var handle uint64
	r, _, _ := procStartTraceW.Call(
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(&nameU16[0])),
		uintptr(unsafe.Pointer(props)),
	)
	if r != 0 {
		return nil, fmt.Errorf("etw: StartTraceW: %w", windows.Errno(r))
	}
	return &Session{handle: handle, name: nameU16}, nil
}

// EnableProvider enables a manifest provider on the session, matching any of the keyword bits (0 means all keywords). Level is fixed at
// informational, which is what the process/network/dns providers emit their lifecycle events at.
func (s *Session) EnableProvider(guid windows.GUID, matchAnyKeyword uint64) error {
	r, _, _ := procEnableTraceEx2.Call(
		uintptr(s.handle),
		uintptr(unsafe.Pointer(&guid)),
		eventControlCodeEnable,
		traceLevelInformation,
		uintptr(matchAnyKeyword),
		uintptr(matchAnyKeyword>>32),
		0,
		0,
	)
	if r != 0 {
		return fmt.Errorf("etw: EnableTraceEx2: %w", windows.Errno(r))
	}
	return nil
}

// Name returns the session's logger name, which a Consumer opens against.
func (s *Session) Name() string { return windows.UTF16ToString(s.name) }

// Stop stops the kernel session. Safe to call once; a stopped session's name can be reused by a later StartSession.
func (s *Session) Stop() error {
	if r := stopByName(s.name); r != 0 {
		return fmt.Errorf("etw: ControlTraceW(stop): %w", windows.Errno(r))
	}
	return nil
}

// stopByName issues EVENT_TRACE_CONTROL_STOP by logger name and returns the raw status (0 on success, or ERROR_WMI_INSTANCE_NOT_FOUND
// when no such session exists, which callers treat as already-stopped).
func stopByName(nameU16 []uint16) uintptr {
	buf := make([]byte, int(unsafe.Sizeof(eventTraceProperties{}))+len(nameU16)*2)
	props := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
	props.Wnode.BufferSize = uint32(len(buf))
	props.LoggerNameOffset = uint32(unsafe.Sizeof(eventTraceProperties{}))
	r, _, _ := procControlTraceW.Call(0, uintptr(unsafe.Pointer(&nameU16[0])), uintptr(unsafe.Pointer(props)), eventTraceControlStop)
	return r
}
