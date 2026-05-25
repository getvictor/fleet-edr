// Package receiver delivers raw JSON event bytes from upstream sources (the
// macOS ESF / Network Extension XPC peer on darwin, a no-op stub elsewhere)
// to a Go channel that the agent's queue + uploader pipeline consumes.
//
// The darwin build is the production receiver and lives in receiver.go +
// callbacks.go + bridge.c. The non-darwin build is the stub in
// receiver_other.go: it satisfies the same public surface so the agent
// module compiles on linux for the headless integration job (UAT plan M3),
// but the stub Receiver's Connect, SendApplicationControl, and Ping all
// return ErrUnsupported because there is no XPC service to talk to. A
// future milestone (M2) replaces the stub with an inject-able variant
// driven by the fake-agent control plane.
package receiver

import (
	"context"
	"log/slog"
	"sync/atomic"
)

// Error codes matching xpc_bridge.h constants. The values are part of the agent's logging surface; main.go classifies which codes are
// "expected" (transient reconnects) versus unexpected via these symbols, so they live in the shared file so the linux build sees them too.
const (
	ErrorConnectionInvalid     = 1
	ErrorConnectionInterrupted = 2
	ErrorTerminated            = 3
)

// Event is a raw JSON event received from an upstream source.
type Event struct {
	Data []byte
}

// logger is the package-level logger used from CGo callbacks where passing a per-request logger would be impractical. Callers can override
// it via SetLogger; the default is slog.Default(). The darwin build's onEvent reads it via getLogger (in receiver.go); the non-darwin stub
// never logs because it never produces events.
var logger atomic.Pointer[slog.Logger]

// SetLogger installs a logger for diagnostic output from the package's
// callback paths. Safe to call concurrently.
func SetLogger(l *slog.Logger) {
	if l != nil {
		logger.Store(l)
	}
}

// getLogger returns the package-level logger or slog.Default if none has been installed. Lives in common.go (rather than the
// darwin/cgo receiver.go) so non-darwin builds can use it AND so tryDeliverEvent below is reachable from tests without CGo.
func getLogger() *slog.Logger {
	if l := logger.Load(); l != nil {
		return l
	}
	return slog.Default()
}

// tryDeliverEvent does a non-blocking send of evt onto ch. When ch's buffer is full it logs a warning naming serviceName and DROPS
// the event without blocking the caller. The production CGo onEvent callback uses this so a slow downstream consumer cannot
// back-pressure into the XPC kernel side; tests exercise it directly to pin the drop-and-warn contract without needing a live
// Mach service. The dropped-event arm is the agent-xpc-receiver "downstream consumer falls behind" scenario: the receiver MUST
// keep reading subsequent events from the connector, so the send is non-blocking and the loss is surfaced via a warning rather
// than a returned error.
func tryDeliverEvent(ch chan<- Event, evt Event, serviceName string) {
	select {
	case ch <- evt:
	default:
		getLogger().WarnContext(context.Background(), "receiver event channel full", "service", serviceName)
	}
}
