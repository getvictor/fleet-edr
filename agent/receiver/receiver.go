// Package receiver connects to XPC Mach services (ESF extension, network extension)
// and delivers raw JSON event bytes to Go channels.
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
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"unsafe"
)

// logger is the package-level logger used from CGo callbacks where passing a per-request logger
// would be impractical. Callers can override it via SetLogger; the default is slog.Default().
var logger atomic.Pointer[slog.Logger]

// SetLogger installs a logger for diagnostic output from CGo callbacks. Safe to call concurrently.
func SetLogger(l *slog.Logger) {
	if l != nil {
		logger.Store(l)
	}
}

func getLogger() *slog.Logger {
	if l := logger.Load(); l != nil {
		return l
	}
	return slog.Default()
}

// Error codes matching xpc_bridge.h constants.
const (
	ErrorConnectionInvalid     = 1
	ErrorConnectionInterrupted = 2
	ErrorTerminated            = 3
)

// Event is a raw JSON event received from an XPC extension.
type Event struct {
	Data []byte
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
		return fmt.Errorf("already connected")
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

// SendPolicy delivers a policy.update XPC message to the peer. Returns an error if the
// connection is not established or the send call rejected the payload. The send is
// asynchronous; a nil error means the message was handed off to XPC, not that the peer
// has acknowledged it — an ack is not part of the wire protocol at Phase 2.
func (r *Receiver) SendPolicy(payload []byte) error {
	r.mu.Lock()
	handle := r.handle
	connected := r.connected
	r.mu.Unlock()

	if !connected || handle < 0 {
		return fmt.Errorf("receiver not connected")
	}
	if len(payload) == 0 {
		return fmt.Errorf("empty policy payload")
	}
	rc := int(C.xpc_bridge_send_policy(C.int(handle), (*C.uint8_t)(unsafe.Pointer(&payload[0])), C.size_t(len(payload))))
	if rc != 0 {
		return fmt.Errorf("xpc_bridge_send_policy returned %d", rc)
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
func onError(receiverID int, errorCode int) {
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
