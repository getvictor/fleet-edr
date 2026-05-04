// Async audit writer. Background goroutine that drains a bounded
// channel into Store.Record so the chokepoint's hot path on read
// actions does not wait on an INSERT.
//
// Sync is the default for every write/deny/auth event (see
// AuditRecorder's doc comment). The async path applies only to
// chokepoint emissions where the action is a read action AND the
// decision was Allow=true AND the actor is non-break-glass. Phase 3's
// audit.read_sampling further filters those events at the chokepoint
// before they reach Submit.
//
// Drop policy on full buffer: drop newest, log to slog at WARN with
// the event payload + an OTel-shaped attribute set so dashboards can
// alert on drop-rate spikes. The slog backend is the audit's
// secondary durable sink under the dual-emit pattern; on a hard kill
// (SIGKILL, OOM) the in-flight queue is lost but slog has it.

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

// DefaultAsyncQueueCap is the default channel capacity. ~8K rows of
// cushion is enough for a multi-minute burst at expected wave-1 read
// volumes without consuming meaningful memory (each AuditEvent is
// well under 1 KB on the wire). Operators tune via
// EDR_AUDIT_ASYNC_QUEUE_CAP.
const DefaultAsyncQueueCap = 8192

// shutdownDrainPerEvent caps how long the graceful-shutdown path
// spends per queued event. Five seconds matches sync Record's
// implicit ceiling under a healthy MySQL; longer than that and the
// shutdown is no longer "graceful" and slog catches the rest.
const shutdownDrainPerEvent = 5 * time.Second

// AsyncWriter implements api.AsyncAuditWriter. Construct via
// NewAsyncWriter and call Run from a goroutine owned by the host
// context's Run method.
type AsyncWriter struct {
	store   *Store
	queue   chan api.AuditEvent
	logger  *slog.Logger
	dropped uint64
	dropMu  sync.Mutex
	stopped chan struct{}
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
		store:   store,
		queue:   make(chan api.AuditEvent, queueCap),
		logger:  logger,
		stopped: make(chan struct{}),
	}
}

// Submit places e on the queue. Non-blocking: returns true on enqueue,
// false when the queue is full or the writer has stopped. On false,
// the writer logs a WARN with the event metadata so the slog backend
// preserves the audit content even though no DB row will be written.
//
// Submit is safe to call concurrently from any goroutine.
func (w *AsyncWriter) Submit(ctx context.Context, e api.AuditEvent) bool {
	select {
	case <-w.stopped:
		w.logDropped(ctx, e, "writer_stopped")
		return false
	default:
	}
	select {
	case w.queue <- e:
		return true
	default:
		w.logDropped(ctx, e, "queue_full")
		return false
	}
}

// Run drains the queue until ctx is cancelled. On cancellation, drains
// remaining queued events with a per-event deadline before returning.
// Returns nil on graceful shutdown; never returns a hard error (an
// INSERT failure is logged and the loop continues).
//
// Recover on panic: a panic inside store.Record (e.g., the *sqlx.DB
// returns an unexpected error type that triggers a deferred panic in
// downstream tooling) must not bring the audit subsystem down. The
// loop catches, logs, and continues.
//
// Per-event ctx: writeOne builds its own bounded context from
// context.Background rather than inheriting Run's ctx. After Run's
// ctx is cancelled, Go's select can still pick the queue branch on a
// race; using a fresh ctx for the INSERT keeps Store.Record from
// failing with "context canceled" on an event that was already
// dequeued. The trace_id propagates via the event itself, not via
// ctx.
func (w *AsyncWriter) Run(ctx context.Context) error {
	defer close(w.stopped)
	for {
		select {
		case <-ctx.Done():
			w.drain()
			return nil
		case e := <-w.queue:
			//nolint:contextcheck // intentional: writeOne builds its
			// own bounded ctx so an INSERT in flight after parent ctx
			// cancellation still completes; trace_id rides on the event.
			w.writeOne(e)
		}
	}
}

// writeOne wraps Store.Record with panic recovery and a fresh bounded
// context. An INSERT error is not a hard error for the writer loop —
// log + continue. The chokepoint's sync path remains the durable
// signal for failure modes where MySQL is genuinely unavailable.
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

// drain flushes pending events on shutdown. Each writeOne call uses
// its own bounded background ctx; the slog secondary keeps the audit
// content durable when the INSERT cannot finish in time. The fresh
// ctx per event is the design, not an oversight — see writeOne.
//
//nolint:contextcheck
func (w *AsyncWriter) drain() {
	for {
		select {
		case e := <-w.queue:
			w.writeOne(e)
		default:
			return
		}
	}
}

// logDropped emits the dual-emit slog WARN that preserves the audit
// content when the bounded buffer cannot. reason is "queue_full" on a
// burst or "writer_stopped" when Submit raced shutdown. Attributes
// mirror the AuditEvent shape so a log-aggregation query can pivot
// from the slog index back to a logical audit row.
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

// ErrAsyncStopped is returned to callers waiting on Run when the
// writer's stopped channel has already been closed and they ask for
// state observation. Today nothing does; reserved for a future
// readiness probe so the symbol is stable.
var ErrAsyncStopped = errors.New("audit: async writer stopped")
