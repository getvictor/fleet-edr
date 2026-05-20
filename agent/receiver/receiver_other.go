//go:build !darwin || !cgo

package receiver

import (
	"errors"
	"time"
)

// ErrUnsupported is returned by Connect, SendApplicationControl, and Ping
// on every non-darwin platform. The agent's production receiver wraps a
// macOS XPC Mach service; outside macOS there is no peer to talk to, so
// the stub fails closed rather than appearing to succeed.
//
// The headless integration binary (UAT plan M2) replaces this stub with
// an inject-able variant so cross-context tests can drive the agent on
// linux. Until that lands, building on linux is for compile-only
// verification, not for running the agent end to end.
var ErrUnsupported = errors.New("receiver: XPC not available on this platform")

// Receiver is the non-darwin stub. It exposes the same public surface as
// the darwin Receiver in receiver.go so the agent's call sites
// (cmd/fleet-edr-agent/main.go) compile without a per-platform import or
// interface indirection.
type Receiver struct {
	serviceName string
	events      chan Event
	errors      chan int
}

// New constructs a stub receiver. The signature matches the darwin
// constructor so callers do not branch on platform.
func New(serviceName string, eventBuf int) *Receiver {
	return &Receiver{
		serviceName: serviceName,
		events:      make(chan Event, eventBuf),
		errors:      make(chan int, 8),
	}
}

// Events returns the channel on which events would be delivered. The stub
// never produces any, so any receive on this channel blocks forever.
func (r *Receiver) Events() <-chan Event { return r.events }

// Errors returns the channel on which connection errors would be
// delivered. The stub never produces any.
func (r *Receiver) Errors() <-chan int { return r.errors }

// Connect always returns ErrUnsupported on non-darwin platforms.
func (r *Receiver) Connect() error { return ErrUnsupported }

// SendApplicationControl always returns ErrUnsupported on non-darwin
// platforms. The signature mirrors the darwin method so commander code
// compiles without a build tag.
func (r *Receiver) SendApplicationControl(payload []byte) error { return ErrUnsupported }

// Ping always returns ErrUnsupported on non-darwin platforms. The
// timeout argument is accepted but unused; preserving the signature lets
// the heartbeat loop in main.go compile.
func (r *Receiver) Ping(timeout time.Duration) error { return ErrUnsupported }

// Disconnect is a no-op on non-darwin platforms. The stub never connects (Connect always returns ErrUnsupported) so there is no XPC
// connection to tear down; Disconnect exists only to satisfy the darwin Receiver's public surface.
func (r *Receiver) Disconnect() {
	// Intentionally empty: stub has no resources to release. See Connect above for the platform-support rationale.
}

// Inject pushes a raw JSON event onto the receiver's Events() channel as if it had arrived from the XPC peer. Only the non-darwin / no-cgo
// stub exposes this entry point; the production XPC receiver receives events from the kernel via the system extension and has no
// in-process injection surface. The headless agent binary (agent/cmd/fleet-edr-agent-headless) uses Inject from its control-plane HTTP
// handler so test scenarios can drive the queue + uploader pipeline without a real ESF extension.
//
// Non-blocking by design: if the events buffer is full (the Receiver was constructed with a fixed buffer in New), Inject returns
// ErrBufferFull immediately rather than blocking the HTTP handler. A test scenario that legitimately needs higher throughput should
// either size the buffer up at construction time or pace its injections.
func (r *Receiver) Inject(b []byte) error {
	select {
	case r.events <- Event{Data: b}:
		return nil
	default:
		return ErrBufferFull
	}
}

// ErrBufferFull is returned by Inject when the events buffer is at capacity.
var ErrBufferFull = errors.New("receiver: event buffer full")
