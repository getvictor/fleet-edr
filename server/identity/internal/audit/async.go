// Async audit writer. Background goroutine that drains a bounded
// channel into Store.Record so the chokepoint's hot path on read
// actions does not wait on an INSERT.
//
// Sync is the default for every write/deny/auth event (see
// AuditRecorder's doc comment). The async path applies only to
// chokepoint emissions where the action is a read action AND the
// decision was Allow=true AND the actor is non-break-glass.
// audit.read_sampling further filters those events at the chokepoint
// before they reach Submit.
//
// Drop policy on full buffer: drop newest, log to slog at WARN with
// the event payload + an OTel-shaped attribute set so dashboards can
// alert on drop-rate spikes. The slog backend is the audit's
// secondary durable sink under the dual-emit pattern; on a hard kill
// (SIGKILL, OOM) the in-flight queue is lost but slog has it.
//
// Shutdown contract: Submit + close-and-drain are mutually exclusive
// via a sync.RWMutex. RLock is the cheap many-reader path Submit
// takes; the shutdown path takes the writer Lock, which blocks until
// all in-flight Submits complete and prevents new ones from
// queuing. drain then runs alone with a global deadline so an
// unresponsive DB cannot stall server shutdown indefinitely.

package audit

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/identity/api"
)

// DefaultAsyncQueueCap is the default channel capacity. ~8K rows of cushion is enough for a multi-minute burst at expected
// wave-1 read volumes without consuming meaningful memory (each AuditEvent is well under 1 KB on the wire). Operators tune via
// EDR_AUDIT_ASYNC_QUEUE_CAP.
const DefaultAsyncQueueCap = 8192

// shutdownDrainPerEvent caps how long a single drained event spends in the INSERT path. Five seconds matches sync Record's implicit
// ceiling under a healthy MySQL.
const shutdownDrainPerEvent = 5 * time.Second

// shutdownDrainGlobal caps the total wall-clock spent draining at shutdown. With 8192 events and a 5s per-event cap, an unresponsive
// DB could otherwise stall shutdown for ~11 hours. 30 seconds keeps the server's shutdown grace window roughly bounded; rows still
// queued past it spill to slog as the dual-emit fallback.
const shutdownDrainGlobal = 30 * time.Second

// AsyncWriter implements api.AsyncAuditWriter. Construct via NewAsyncWriter and call Run from a goroutine owned by the host context's
// Run method.
type AsyncWriter struct {
	store   *Store
	queue   chan api.AuditEvent
	logger  *slog.Logger
	dropped uint64
	dropMu  sync.Mutex

	// submitMu serializes Submit (RLock) against shutdown (Lock). shutdown.Lock() blocks until every in-flight Submit has released its
	// RLock, then sets closed=true under the write lock so subsequent Submits see the closed flag and return false without queuing.
	// This eliminates the race where a Submit could enqueue an event after drain has already returned.
	submitMu sync.RWMutex
	closed   bool
}

// AsyncOptions configures NewAsyncWriter. Zero values mean defaults.
type AsyncOptions struct {
	// QueueCap sizes the bounded channel. Zero -> DefaultAsyncQueueCap.
	QueueCap int
	// Logger receives drop / shutdown / panic warnings. Zero ->
	// slog.Default.
	Logger *slog.Logger
}

// NewAsyncWriter constructs an AsyncWriter. The returned writer is
// safe to call Submit on immediately; Run must also be invoked (in a
// separate goroutine) for events to actually drain to the store.
//
// Panics if store is nil — a writer that buffers events with nowhere
// to send them is a footgun and exists only as a programming error.
func NewAsyncWriter(store *Store, opts AsyncOptions) *AsyncWriter {
	if store == nil {
		panic("audit.NewAsyncWriter: store must not be nil")
	}
	queueCap := opts.QueueCap
	if queueCap <= 0 {
		queueCap = DefaultAsyncQueueCap
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &AsyncWriter{
		store:  store,
		queue:  make(chan api.AuditEvent, queueCap),
		logger: logger,
	}
}

// Submit places e on the queue. Non-blocking: returns true on enqueue,
// false when the writer has closed (shutdown in progress) or the
// queue is full. On false the writer logs a WARN with the event
// metadata so the slog backend preserves the audit content even
// though no DB row will be written.
//
// Submit is safe to call concurrently from any goroutine. The RLock
// is held only for the duration of the channel send; once Submit
// returns, no further locks are held and the eventual INSERT runs
// under the writer's Run goroutine with its own background ctx.
func (w *AsyncWriter) Submit(ctx context.Context, e api.AuditEvent) bool {
	w.submitMu.RLock()
	defer w.submitMu.RUnlock()
	if w.closed {
		w.logDropped(ctx, e, "writer_stopped")
		return false
	}
	select {
	case w.queue <- e:
		return true
	default:
		w.logDropped(ctx, e, "queue_full")
		return false
	}
}

// Run drains the queue until ctx is cancelled. On cancellation, the
// shutdown path takes submitMu.Lock(), sets closed=true so concurrent
// Submits return false without queuing, then drains remaining events
// under a global deadline before returning. Returns nil on graceful
// shutdown; never returns a hard error (an INSERT failure is logged
// and the loop continues).
//
// Recover on panic: a panic inside store.Record (e.g., the *sqlx.DB
// returns an unexpected error type that triggers a deferred panic in
// downstream tooling) must not bring the audit subsystem down. The
// loop catches, logs, and continues.
func (w *AsyncWriter) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			w.shutdown()
			return nil
		case e := <-w.queue:
			// nolint:contextcheck // intentional: writeOne builds its own bounded ctx so an INSERT in flight after parent
			// ctx cancellation still completes; trace_id rides on the event.
			w.writeOne(e)
		}
	}
}

// shutdown closes the writer to new submits and drains the queue under a global deadline. Holds submitMu.Lock() across the closed flip
// so no new Submit can enqueue an event between the closure and the drain (CodeRabbit + Gemini PR #120 review).
func (w *AsyncWriter) shutdown() {
	w.submitMu.Lock()
	w.closed = true
	w.submitMu.Unlock()
	w.drain()
}

// writeOne wraps Store.Record with panic recovery and a fresh bounded context. An INSERT error is not a hard error for the writer loop
// — log + continue. The chokepoint's sync path remains the durable signal for failure modes where MySQL is genuinely unavailable.
func (w *AsyncWriter) writeOne(e api.AuditEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownDrainPerEvent)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			w.logger.WarnContext(ctx, "audit async record panic recovered",
				"panic", r,
				"action", string(e.Action))
		}
	}()
	if err := w.store.Record(ctx, e); err != nil {
		w.logger.WarnContext(ctx, "audit async record failed",
			"err", err,
			"action", string(e.Action),
			"target_type", e.TargetType,
			"target_id", e.TargetID)
	}
}

// drain flushes pending events on shutdown. Bounded by a global
// wall-clock deadline so a slow / unresponsive DB cannot stall
// shutdown indefinitely; rows still in the queue past the deadline
// log to slog as the dual-emit fallback.
//
//nolint:contextcheck
func (w *AsyncWriter) drain() {
	deadline := time.Now().Add(shutdownDrainGlobal)
	for {
		if !time.Now().Before(deadline) {
			w.logUndrainedTail()
			return
		}
		select {
		case e := <-w.queue:
			w.writeOne(e)
		default:
			return
		}
	}
}

// logUndrainedTail emits a slog WARN per still-queued event when the global drain deadline expires. Each WARN carries the event
// payload so post-incident log scraping can reconstruct what didn't land.
func (w *AsyncWriter) logUndrainedTail() {
	for {
		select {
		case e := <-w.queue:
			w.logDropped(context.Background(), e, "drain_deadline_exceeded")
		default:
			return
		}
	}
}

// logDropped emits the dual-emit slog WARN that preserves the audit content when the bounded buffer cannot. reason is "queue_full" on
// a burst, "writer_stopped" when Submit raced shutdown, or "drain_deadline_exceeded" when the global drain ran out of time. Attributes
// mirror the AuditEvent shape so a log-aggregation query can pivot from the slog index back to a logical audit row.
func (w *AsyncWriter) logDropped(ctx context.Context, e api.AuditEvent, reason string) {
	w.dropMu.Lock()
	w.dropped++
	w.dropMu.Unlock()
	uid := int64(0)
	if e.UserID != nil {
		uid = *e.UserID
	}
	attrs := []any{
		"reason", reason,
		"action", string(e.Action),
		"target_type", e.TargetType,
		"target_id", e.TargetID,
		"actor_email", e.ActorEmail,
		attrkeys.UserID, uid,
	}
	if e.TraceID != "" {
		attrs = append(attrs, "trace_id", e.TraceID)
	}
	if len(e.Payload) > 0 {
		attrs = append(attrs, "payload", e.Payload)
	}
	w.logger.WarnContext(ctx, "audit dropped (async queue)", attrs...)
}

// Dropped returns the count of events dropped since construction. Used
// by tests; production observability rides on the slog backend.
func (w *AsyncWriter) Dropped() uint64 {
	w.dropMu.Lock()
	defer w.dropMu.Unlock()
	return w.dropped
}

// ErrAsyncStopped is returned to callers waiting on Run when the writer has already shut down and they ask for state observation.
// Today nothing does; reserved for a future readiness probe so the symbol is stable.
var ErrAsyncStopped = errors.New("audit: async writer stopped")
