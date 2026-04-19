// Package metrics owns the agent-side OTel metric surface. Right now the only write
// surface is queue drop accounting; adding more instruments later (upload latency,
// batch retries, etc.) should happen here so attribute keys stay centralised.
package metrics

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const meterName = "github.com/fleetdm/edr/agent/metrics"

// Recorder is the nil-safe write surface agent components use. Backed by the global
// OTel meter; when `observability.Init` leaves the SDK at its no-op default (no
// OTEL_EXPORTER_OTLP_ENDPOINT set), Add is a no-op and the Recorder costs nothing.
type Recorder struct {
	queueDropped metric.Int64Counter
}

// New builds a Recorder wired against the global OTel meter. Host identity is
// carried on the OTLP resource (set by observability.Init), not on the counter
// attribute set, so per-host drop rates come for free in SigNoz without
// inflating cardinality on every sample.
func New() *Recorder {
	m := otel.Meter(meterName)
	r := &Recorder{}
	r.queueDropped, _ = m.Int64Counter(
		"edr.agent.queue.dropped",
		metric.WithDescription("Events dropped by the agent queue cap. Attribute `lossy=true` means data loss; `lossy=false` means already-delivered rows trimmed for space."),
		metric.WithUnit("{event}"),
	)
	return r
}

// QueueDropped satisfies queue.DroppedMetrics. Nil-safe: a zero Recorder discards the
// call silently so callers can ignore the "did Init succeed" question.
func (r *Recorder) QueueDropped(ctx context.Context, n int64, lossy bool) {
	if r == nil || r.queueDropped == nil || n <= 0 {
		return
	}
	r.queueDropped.Add(ctx, n, metric.WithAttributes(attribute.Bool("lossy", lossy)))
}
