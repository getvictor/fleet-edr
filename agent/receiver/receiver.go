// Package receiver connects to the ESF system extension over XPC and delivers
// raw JSON event bytes to a Go channel.
package receiver

/*
#cgo CFLAGS: -I${SRCDIR}/../xpcbridge
#cgo LDFLAGS: -framework Foundation

#include "xpc_bridge.h"
#include <stdlib.h>

extern int bridge_connect_go(const char *service_name);
*/
import "C"

import (
	"context"
	"fmt"
	"log"
	"sync"
	"unsafe"
)

// Error codes matching xpc_bridge.h constants.
const (
	ErrorConnectionInvalid     = 1
	ErrorConnectionInterrupted = 2
	ErrorTerminated            = 3
)

// Event is a raw JSON event received from the ESF extension.
type Event struct {
	Data []byte
}

// Receiver manages the XPC connection and delivers events.
type Receiver struct {
	serviceName string
	events      chan Event
	errors      chan int
	mu          sync.Mutex
	connected   bool
}

// global receiver instance referenced by C callbacks.
var (
	globalReceiver   *Receiver
	globalReceiverMu sync.Mutex
)

// New creates a Receiver for the given XPC Mach service name.
// eventBuf controls the channel buffer size.
func New(serviceName string, eventBuf int) *Receiver {
	return &Receiver{
		serviceName: serviceName,
		events:      make(chan Event, eventBuf),
		errors:      make(chan int, 8),
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

// Connect establishes the XPC connection. Only one Receiver may be connected
// at a time (the C shim uses global state).
func (r *Receiver) Connect() error {
	globalReceiverMu.Lock()
	if globalReceiver != nil {
		globalReceiverMu.Unlock()
		return fmt.Errorf("another receiver is already connected")
	}
	globalReceiver = r
	globalReceiverMu.Unlock()

	r.mu.Lock()
	defer r.mu.Unlock()

	cName := C.CString(r.serviceName)
	defer C.free(unsafe.Pointer(cName))

	rc := C.bridge_connect_go(cName)
	if rc != 0 {
		globalReceiverMu.Lock()
		globalReceiver = nil
		globalReceiverMu.Unlock()
		return fmt.Errorf("xpc_bridge_connect failed with code %d", rc)
	}
	r.connected = true
	return nil
}

// Disconnect tears down the XPC connection.
func (r *Receiver) Disconnect() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.connected {
		C.xpc_bridge_disconnect()
		r.connected = false
	}

	globalReceiverMu.Lock()
	if globalReceiver == r {
		globalReceiver = nil
	}
	globalReceiverMu.Unlock()
}

// Run connects and blocks until the context is cancelled, logging received events.
func (r *Receiver) Run(ctx context.Context) error {
	if err := r.Connect(); err != nil {
		return err
	}
	defer r.Disconnect()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case evt := <-r.events:
			log.Printf("event received: %s", string(evt.Data))
		case errCode := <-r.errors:
			log.Printf("xpc error: %d", errCode)
		}
	}
}

// onEvent is called from C (via callbacks.go) when an XPC event message arrives.
func onEvent(data unsafe.Pointer, length int) {
	globalReceiverMu.Lock()
	recv := globalReceiver
	globalReceiverMu.Unlock()

	if recv == nil {
		return
	}

	buf := C.GoBytes(data, C.int(length))

	select {
	case recv.events <- Event{Data: buf}:
	default:
		log.Println("receiver: event channel full, dropping event")
	}
}

// onError is called from C (via callbacks.go) when an XPC connection error occurs.
func onError(errorCode int) {
	globalReceiverMu.Lock()
	recv := globalReceiver
	globalReceiverMu.Unlock()

	if recv == nil {
		return
	}

	select {
	case recv.errors <- errorCode:
	default:
	}
}
