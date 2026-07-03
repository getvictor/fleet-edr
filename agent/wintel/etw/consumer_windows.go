//go:build windows

package etw

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procOpenTraceW   = advapi32.NewProc("OpenTraceW")
	procProcessTrace = advapi32.NewProc("ProcessTrace")
	procCloseTrace   = advapi32.NewProc("CloseTrace")
)

// eventRecordCallbackPtr is the single, process-wide stdcall stub for the ETW EVENT_RECORD callback. windows.NewCallback allocates a
// runtime stub that is never released and the process is capped at a small number of them, so it is created once here rather than per
// OpenConsumer (which would leak a stub on every reconnect and eventually panic). The callback carries no closure state; it dispatches
// through the handlerReg package-global.
var eventRecordCallbackPtr = windows.NewCallback(eventRecordCallback)

// handlerReg holds the single active consumer's handler. ETW's EVENT_RECORD callback (installed via windows.NewCallback) carries no Go
// closure state, and the agent runs exactly one ETW consumer, so the handler is kept in a package-global guarded by a mutex rather than
// threaded through EVENT_RECORD.UserContext. OpenConsumer rejects a second concurrent consumer so this stays unambiguous.
var handlerReg struct {
	mu      sync.Mutex
	handler func(Record)
	active  bool
}

// Consumer reads events from a real-time session and dispatches each to a handler. Process blocks until the session stops, so callers
// run it on its own goroutine and call the owning Session's Stop to unblock it.
type Consumer struct {
	trace uintptr
}

// OpenConsumer opens the named session for real-time, event-record consumption. handler is invoked on the ProcessTrace thread for every
// event; it must not block for long and must not panic. Only one consumer may be open per process at a time.
func OpenConsumer(sessionName string, handler func(Record)) (*Consumer, error) {
	if handler == nil {
		return nil, fmt.Errorf("etw: nil handler")
	}
	handlerReg.mu.Lock()
	if handlerReg.active {
		handlerReg.mu.Unlock()
		return nil, fmt.Errorf("etw: a consumer is already active in this process")
	}
	handlerReg.handler = handler
	handlerReg.active = true
	handlerReg.mu.Unlock()

	nameU16, err := windows.UTF16FromString(sessionName)
	if err != nil {
		releaseHandler()
		return nil, fmt.Errorf("etw: encode session name: %w", err)
	}
	var logfile eventTraceLogfile
	logfile.LoggerName = &nameU16[0]
	logfile.ProcessTraceMode = processTraceModeRealTime | processTraceModeEventRec
	logfile.Callback = eventRecordCallbackPtr

	trace, _, _ := procOpenTraceW.Call(uintptr(unsafe.Pointer(&logfile)))
	if trace == invalidProcessTraceHandle {
		releaseHandler()
		return nil, fmt.Errorf("etw: OpenTraceW: %w", windows.GetLastError())
	}
	return &Consumer{trace: trace}, nil
}

// Process delivers events to the handler until the session is stopped (or an error occurs). It blocks; run it on a goroutine.
func (c *Consumer) Process() error {
	th := c.trace
	// ProcessTrace(&handle, 1, nil, nil): consume one trace from now until the session stops.
	r, _, _ := procProcessTrace.Call(uintptr(unsafe.Pointer(&th)), 1, 0, 0)
	if r != 0 {
		return fmt.Errorf("etw: ProcessTrace: %w", windows.Errno(r))
	}
	return nil
}

// Close closes the trace handle and releases the process-global handler slot. Closing a real-time trace while ProcessTrace is still
// running is the documented way to unblock it: CloseTrace returns ERROR_CTX_CLOSE_PENDING (treated as success below) and ProcessTrace
// then drains its buffers and returns. So the teardown order is Close (to stop Process) and only then wait for the Process goroutine.
func (c *Consumer) Close() error {
	r, _, _ := procCloseTrace.Call(c.trace)
	releaseHandler()
	// ERROR_CTX_CLOSE_PENDING (7007) means the close completes when ProcessTrace returns; treat it as success.
	if r != 0 && r != 7007 {
		return fmt.Errorf("etw: CloseTrace: %w", windows.Errno(r))
	}
	return nil
}

func releaseHandler() {
	handlerReg.mu.Lock()
	handlerReg.handler = nil
	handlerReg.active = false
	handlerReg.mu.Unlock()
}

// eventRecordCallback is the ETW EVENT_RECORD callback. It runs on the ProcessTrace thread; it looks up the active handler and invokes
// it with a Record wrapping the native pointer. A nil handler (during teardown) drops the event.
func eventRecordCallback(rec *eventRecord) uintptr {
	handlerReg.mu.Lock()
	h := handlerReg.handler
	handlerReg.mu.Unlock()
	if h == nil {
		return 0
	}
	// A panic must not unwind across the OS callback boundary: that would tear down the ProcessTrace thread and crash the agent. Fail
	// closed by recovering here, which drops the offending event and lets tracing continue.
	defer func() { _ = recover() }()
	h(Record{p: rec})
	return 0
}
