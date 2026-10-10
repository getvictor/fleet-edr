package pipeline

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

// tracer returns the tracer for the root spans of the pipeline's background work: one per claimed host batch (api.BatchSpanName)
// and one per periodic sweep pass. Nothing upstream of either holds a span, so without these the work's queries had no parent: each
// exported as its own root span, which the route-tier sampler could not classify and kept at 100%. Resolved from the global provider
// on each call rather than captured once, so it always reaches the provider installed at startup (and the one a test installs).
func tracer() trace.Tracer {
	return otel.GetTracerProvider().Tracer("github.com/fleetdm/edr/server/detection/internal/pipeline")
}
