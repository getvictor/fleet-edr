//go:build darwin && cgo

// This file contains the production XPC-backed Receiver. Shared identifiers (Event, Error* constants, logger plumbing) live in common.go
// so the non-darwin stub in receiver_other.go can reuse them without duplication. The `cgo` build constraint pairs with the stub's
// `!darwin || !cgo` so a `GOOS=darwin CGO_ENABLED=0` build still resolves the Receiver type via the stub instead of failing with
// missing symbols.
package receiver

/*
#cgo CFLAGS: -I${SRCDIR}/../xpcbridge
#cgo LDFLAGS: -framework Foundation

#include "xpc_bridge.h"
#include <stdlib.h>
#include <stdint.h>

extern int bridge_connect_go(const char *service_name, int receiver_id);
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
	"unsafe"
)

func getLogger() *slog.Logger {
	if l := logger.Load(); l != nil {
		return l
	}
	return slog.Default()
}

// Receiver manages a single XPC connection and delivers events.
type Receiver struct {
	serviceName string
	events      chan Event
	errors      chan int
	mu          sync.Mutex
	connected   bool
	handle      int // C bridge connection handle, -1 when not connected
	receiverID  int // ID used to route C callbacks to this receiver
}

// Registry of active receivers, keyed by receiverID.
var (
	receivers   = make(map[int]*Receiver)
	receiversMu sync.Mutex
	nextID      int
)

// New creates a Receiver for the given XPC Mach service name.
// eventBuf controls the channel buffer size.
func New(serviceName string, eventBuf int) *Receiver {
	receiversMu.Lock()
	id := nextID
	nextID++
	receiversMu.Unlock()

	return &Receiver{
		serviceName: serviceName,
		events:      make(chan Event, eventBuf),
		errors:      make(chan int, 8),
		handle:      -1,
		receiverID:  id,
	}
}

// Events returns the channel on which received events are delivered.
func (r *Receiver) Events() <-chan Event {
	return r.events
}

// Errors returns the channel on which connection errors are delivered.
func (r *Receiver) Errors() <-chan int {
	return r.errors
}

// Connect establishes the XPC connection. Multiple receivers may be
// connected simultaneously to different XPC services.
func (r *Receiver) Connect() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.connected {
		return errors.New("already connected")
	}

	// Register in the global map so C callbacks can find us.
	receiversMu.Lock()
	receivers[r.receiverID] = r
	receiversMu.Unlock()

	cName := C.CString(r.serviceName)
	defer C.free(unsafe.Pointer(cName))

	handle := int(C.bridge_connect_go(cName, C.int(r.receiverID)))
	if handle < 0 {
		receiversMu.Lock()
		delete(receivers, r.receiverID)
		receiversMu.Unlock()
		return fmt.Errorf("xpc_bridge_connect failed for %s", r.serviceName)
	}

	r.handle = handle
	r.connected = true
	return nil
}

// SendApplicationControl delivers an `application_control.update` XPC message
// to the peer. Returns an error if the connection is not established or the
// send call rejected the payload. The send is asynchronous; a nil error means
// the message was handed off to XPC, not that the peer has acknowledged it —
// an ack is not part of the current wire protocol.
//
// We hold r.mu across the C bridge call so a concurrent Disconnect() cannot
// tear the slot down while C is still using the handle. Without the extended
// lock, the small integer handle could be reused by another Receiver's
// Connect between our snapshot and the xpc_bridge_send_application_control
// call, and we'd end up sending this host's payload on a different peer's
// connection.
func (r *Receiver) SendApplicationControl(payload []byte) error {
	if len(payload) == 0 {
		return errors.New("empty application_control payload")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.connected || r.handle < 0 {
		return errors.New("receiver not connected")
	}
	rc := int(C.xpc_bridge_send_application_control(C.int(r.handle), (*C.uint8_t)(unsafe.Pointer(&payload[0])), C.size_t(len(payload))))
	if rc != 0 {
		return fmt.Errorf("xpc_bridge_send_application_control returned %d", rc)
	}
	return nil
}

// Ping sends a "hello" handshake message to the peer and blocks until the
// peer's "hello-ack" reply arrives or the timeout fires. Returns nil on a
// successful round-trip and an error on timeout or connection teardown.
//
// Issue #178: macOS XPC can silently route an open connection to a stale
// Mach port after a system-extension respawn, with no error event ever
// surfacing. Ping is the agent's positive liveness probe — call it
// periodically; a failure is the signal to reconnect.
//
// We snapshot the handle under r.mu but release the lock before calling
// into the C bridge so a long ping cannot block Disconnect or SendApplicationControl.
// The C side retains the connection + semaphore for the duration of the wait,
// so a concurrent Disconnect cannot free them out from under us. A Disconnect
// that races with this call will cause the in-flight ping to return -1 (the
// slot snapshot will observe in_use=0 on the next attempt; in-flight waits
// fall through cleanly on cancellation).
func (r *Receiver) Ping(timeout time.Duration) error {
	r.mu.Lock()
	handle := r.handle
	connected := r.connected
	r.mu.Unlock()
	if !connected || handle < 0 {
		return errors.New("receiver not connected")
	}
	if timeout <= 0 {
		return errors.New("ping timeout must be positive")
	}
	rc := int(C.xpc_bridge_ping(C.int(handle), C.uint64_t(timeout.Nanoseconds())))
	if rc != 0 {
		// The C bridge collapses "timeout waiting for hello-ack" and "slot
		// torn down concurrently" into a single -1 — the caller's response
		// (force a reconnect) is the same either way, so distinguishing the
		// two doesn't change behaviour. The error string names the service
		// and timeout so the warning log lines that wrap this error are
		// actionable on their own, without the reader having to cross-
		// reference the receiver instance.
		return fmt.Errorf("xpc ping to %q timed out or connection torn down (timeout %s)", r.serviceName, timeout)
	}
	return nil
}

// Disconnect tears down the XPC connection.
func (r *Receiver) Disconnect() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.connected {
		C.xpc_bridge_disconnect(C.int(r.handle))
		r.connected = false
		r.handle = -1
	}

	receiversMu.Lock()
	delete(receivers, r.receiverID)
	receiversMu.Unlock()
}

// onEvent is called from C (via callbacks.go) when an XPC event message arrives.
func onEvent(receiverID int, data unsafe.Pointer, length int) {
	receiversMu.Lock()
	recv := receivers[receiverID]
	receiversMu.Unlock()

	if recv == nil {
		return
	}

	buf := C.GoBytes(data, C.int(length))

	select {
	case recv.events <- Event{Data: buf}:
	default:
		getLogger().WarnContext(context.Background(), "receiver event channel full", "service", recv.serviceName)
	}
}

// onError is called from C (via callbacks.go) when an XPC connection error occurs.
func onError(receiverID, errorCode int) {
	receiversMu.Lock()
	recv := receivers[receiverID]
	receiversMu.Unlock()

	if recv == nil {
		return
	}

	select {
	case recv.errors <- errorCode:
	default:
	}
}
