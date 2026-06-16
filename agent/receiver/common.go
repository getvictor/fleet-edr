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
	"sync"
	"sync/atomic"
	"time"
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

// dropWarnInterval is the minimum gap between aggregated "channel full" warnings for one receiver. The first drop after a quiet
// period logs immediately so operators see the onset promptly; further drops within the interval are counted and folded into the
// next summary. A sustained overflow therefore collapses from one log line per dropped event (which floods the agent log when a
// slow consumer falls behind, the loss surfaced via the agent-xpc-receiver "downstream consumer falls behind" scenario) to one
// warning per interval carrying the dropped-event count.
const dropWarnInterval = 5 * time.Second

// dropReporter coalesces a single receiver's "channel full" warnings so a burst of drops does not flood the log. Each Receiver
// owns one reporter (one Mach service per receiver), which is why the state is a single counter rather than a per-service map and
// why there is no package-level global: keeping it on the Receiver gives clean test isolation and avoids cross-receiver lock
// contention on the drop path. It tracks the drops accumulated since the last emitted warning and when that warning fired.
type dropReporter struct {
	mu       sync.Mutex
	pending  int64            // drops accumulated since the last emitted warning, not yet reflected in any log line
	lastEmit time.Time        // when the last warning fired; zero until the first drop is reported
	now      func() time.Time // seam for deterministic tests; defaults to time.Now
}

func newDropReporter() *dropReporter {
	return &dropReporter{now: time.Now}
}

// record registers one dropped event. It returns (count, true) when a warning should be emitted now, where count is the number
// of drops the warning accounts for (this drop plus any suppressed since the last warning), or (0, false) when the drop is
// suppressed. Suppressed drops stay in pending and are reported by the next warning that crosses the interval, so the only
// undercount is a trailing partial window after drops stop entirely, at which point the condition has already been logged.
func (r *dropReporter) record() (int64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending++
	now := r.now()
	if r.lastEmit.IsZero() || now.Sub(r.lastEmit) >= dropWarnInterval {
		count := r.pending
		r.pending = 0
		r.lastEmit = now
		return count, true
	}
	return 0, false
}

// tryDeliverEvent does a non-blocking send of evt onto ch. When ch's buffer is full it DROPS the event without blocking the
// caller and surfaces the loss via a rate-limited warning naming serviceName and the dropped-event count, throttled by dr. The
// production CGo onEvent callback uses this so a slow downstream consumer cannot back-pressure into the XPC kernel side; tests
// exercise it directly to pin the drop-and-warn contract without needing a live Mach service. The dropped-event arm is the
// agent-xpc-receiver "downstream consumer falls behind" scenario: the receiver MUST keep reading subsequent events from the
// connector, so the send is non-blocking and the loss is surfaced via a warning rather than a returned error. The warning is
// coalesced per receiver (see dropReporter) so a sustained overflow does not flood the log.
func tryDeliverEvent(ch chan<- Event, evt Event, serviceName string, dr *dropReporter) {
	select {
	case ch <- evt:
	default:
		if count, emit := dr.record(); emit {
			getLogger().WarnContext(context.Background(), "receiver event channel full", "service", serviceName, "dropped", count)
		}
	}
}
