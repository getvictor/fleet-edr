package tracingpolicy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/fleetdm/edr/internal/observability/tracing"
	detectionapi "github.com/fleetdm/edr/server/detection/api"
)

func TestRegister_classifiesRoutesByTier(t *testing.T) {
	t.Parallel()
	reg := tracing.NewRegistry()
	Register(reg)

	cases := []struct {
		span string
		want tracing.Tier
	}{
		{"POST /api/events", tracing.TierHighVolume},
		{"GET /api/commands", tracing.TierHighVolume},
		{"POST /api/token/refresh", tracing.TierHighVolume},
		// Enrollment is rare + load-bearing, so it is intentionally NOT high-volume; it falls to Full (100%).
		{"POST /api/enroll", tracing.TierFull},
		{"GET /api/hosts", tracing.TierStandard},
		{"GET /api/containment", tracing.TierStandard},
		{"GET /api/alerts", tracing.TierStandard},
		{"GET /api/settings/tracing", tracing.TierStandard},
		{"GET /livez", tracing.TierDrop},
		{"GET /readyz", tracing.TierDrop},
		{"GET /health", tracing.TierDrop},
		// A parameter-bearing operator detail read is not classified (otelhttp emits the raw path), so it falls to full fidelity.
		{"GET /api/alerts/42", tracing.TierFull},
		{"GET /api/commands/abc-123", tracing.TierFull},
		// An unknown route falls to full fidelity.
		{"POST /api/brand-new", tracing.TierFull},
		// Background work is classified by its root span name: the detection batch scales with ingest, the sweeps do not.
		{detectionapi.BatchSpanName, tracing.TierHighVolume},
		{"detection.periodic.retention", tracing.TierFull},
	}
	for _, tc := range cases {
		t.Run(tc.span, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, reg.Lookup(tc.span))
		})
	}
}

// The server installs the route-tier sampler behind sdktrace.ParentBased, so a batch's sampling decision is made once, on its root
// span, and the rule-evaluation and query spans under it inherit it. Driven through a real provider with the production policy so a
// batch span left unclassified (and so kept at 100%) or a child that decided for itself would both fail here.
//
// spec:observability-instrumentation/background-work-is-traced-under-a-sampled-root-span/a-detection-batch-is-sampled-as-one-unit
func TestRegister_detectionBatchIsSampledAsOneUnit(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name            string
		highVolumeRatio float64
		wantExported    int
	}{
		{"high-volume ratio 0 exports nothing from the batch", 0, 0},
		{"high-volume ratio 1 exports the batch and its children", 1, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reg := tracing.NewRegistry()
			Register(reg)
			sampler := tracing.NewRouteTierSampler(reg)
			sampler.Apply(tc.highVolumeRatio, 1, false)
			recorder := tracetest.NewSpanRecorder()
			provider := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.ParentBased(sampler)), sdktrace.WithSpanProcessor(recorder))
			t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
			tracer := provider.Tracer("test")

			ctx, batch := tracer.Start(context.Background(), detectionapi.BatchSpanName)
			for _, child := range []string{"detection.rule.evaluate", "sql.stmt.exec"} {
				_, span := tracer.Start(ctx, child)
				span.End()
			}
			batch.End()

			assert.Len(t, recorder.Ended(), tc.wantExported)
		})
	}
}
