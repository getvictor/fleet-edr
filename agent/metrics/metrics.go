// Package metrics owns the agent-side OTel metric surface. The write surfaces today are queue-drop accounting, the uploader's
// per-event-dropped-too-large counter, and the queue-depth observable gauge. Adding more instruments later (upload latency,
// batch retries, etc.) should happen here so attribute keys stay centralised.
package metrics

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const meterName = "github.com/fleetdm/edr/agent/metrics"

// gaugeCallbackTimeout caps each observable-gauge callback so a wedged source (e.g. a SQLite WAL contention spike) cannot
// hold the OTel collection cycle indefinitely. 2s mirrors the server-side gauges in server/metrics — long enough for a
// stalled DB read to either complete or surface the timeout cleanly.
const gaugeCallbackTimeout = 2 * time.Second

// QueueDepthSource is the read-only contract the queue-depth observable gauge calls every collection. *queue.Queue satisfies
// it (Depth(ctx) (int64, error)); passing nil to New disables the gauge so tests + dev paths without a queue don't have to
// invent a stub.
type QueueDepthSource interface {
	Depth(ctx context.Context) (int64, error)
}

// Recorder is the nil-safe write surface agent components use. Backed by the global OTel meter; when `observability.Init`
// leaves the SDK at its no-op default (no OTEL_EXPORTER_OTLP_ENDPOINT set), Add is a no-op and the Recorder costs nothing.
//
// The observable-gauge fields are retained for GC reasons only — OTel's Int64ObservableGauge keeps a closure that captures
// the source; dropping the *gauge reference would let the runtime collect the registration and the callback would stop
// firing on the next GC cycle.
type Recorder struct {
	queueDropped          metric.Int64Counter
	eventsDroppedTooLarge metric.Int64Counter
	queueDepth            metric.Int64ObservableGauge
}

// New builds a Recorder against the global OTel meter. The queue-depth observable gauge is registered when depthSrc is
// non-nil; pass nil from tests / setup paths where no queue exists yet.
func New(depthSrc QueueDepthSource) *Recorder {
	return NewWithMeter(depthSrc, otel.Meter(meterName))
}

// NewWithMeter is the test-injection seam New delegates to. Lets unit tests build a Recorder against a meter backed by a
// sdkmetric.ManualReader so they can collect samples synchronously without leaking state across tests via the global meter
// provider. Production code calls New, not NewWithMeter.
func NewWithMeter(depthSrc QueueDepthSource, m metric.Meter) *Recorder {
	r := &Recorder{}
	r.queueDropped, _ = m.Int64Counter(
		"edr.agent.queue.dropped",
		metric.WithDescription("Events dropped by the agent queue cap. Attribute `lossy=true` means data loss; `lossy=false` means already-delivered rows trimmed for space."),
		metric.WithUnit("{event}"),
	)
	r.eventsDroppedTooLarge, _ = m.Int64Counter(
		"edr.agent.uploader.events_dropped_too_large",
		metric.WithDescription("Events the uploader dropped after a single-event batch was rejected by the server with HTTP 413 `body_too_large`. A non-zero rate indicates an agent producing events larger than the server's per-request cap."),
		metric.WithUnit("{event}"),
	)
	if depthSrc != nil {
		r.queueDepth, _ = m.Int64ObservableGauge(
			"edr.agent.queue.depth",
			metric.WithDescription("Number of events queued for upload (uploaded=0 rows). A rising value indicates the uploader is falling behind the producer."),
			metric.WithUnit("{event}"),
			metric.WithInt64Callback(func(ctx context.Context, obs metric.Int64Observer) error {
				gaugeCtx, cancel := context.WithTimeout(ctx, gaugeCallbackTimeout)
				defer cancel()
				n, err := depthSrc.Depth(gaugeCtx)
				if err != nil {
					// A slow or failing queue must not drop every collection cycle; log so an
					// operator staring at a flat/absent `edr.agent.queue.depth` has a breadcrumb.
					slog.Default().WarnContext(ctx, "edr.agent.queue.depth gauge callback failed", "err", err)
					return nil
				}
				obs.Observe(n)
				return nil
			}),
		)
	}
	return r
}

// QueueDropped satisfies queue.MetricsRecorder. Nil-safe: a zero Recorder discards the
// call silently so callers can ignore the "did Init succeed" question.
func (r *Recorder) QueueDropped(ctx context.Context, n int64, lossy bool) {
	if r == nil || r.queueDropped == nil || n <= 0 {
		return
	}
	r.queueDropped.Add(ctx, n, metric.WithAttributes(attribute.Bool("lossy", lossy)))
}

// EventsDroppedTooLarge increments the uploader's per-event-dropped-too-large counter. Called exactly once per dropped event
// (the recursive split converges on single-event leaves; only the leaves that still 413 are dropped). Nil-safe; n<=0 is a
// no-op so the caller doesn't have to special-case the "already-delivered" path.
func (r *Recorder) EventsDroppedTooLarge(ctx context.Context, n int64) {
	if r == nil || r.eventsDroppedTooLarge == nil || n <= 0 {
		return
	}
	r.eventsDroppedTooLarge.Add(ctx, n)
}
