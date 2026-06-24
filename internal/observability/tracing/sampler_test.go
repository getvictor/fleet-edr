package tracing

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// aTraceID is an arbitrary non-zero trace ID. With ratios pinned to 0 or 1 the specific value is irrelevant (TraceIDRatioBased(0)
// never samples, (1) always), so tests stay deterministic.
var aTraceID = trace.TraceID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

func params(name string) sdktrace.SamplingParameters {
	return sdktrace.SamplingParameters{
		ParentContext: context.Background(),
		TraceID:       aTraceID,
		Name:          name,
		Kind:          trace.SpanKindServer,
	}
}

func isSampled(r sdktrace.SamplingResult) bool { return r.Decision == sdktrace.RecordAndSample }

func newSamplerWithPolicy() (*RouteTierSampler, *Registry) {
	reg := NewRegistry()
	reg.Register("POST", "/api/events", TierHighVolume)
	reg.Register("GET", "/api/hosts", TierStandard)
	reg.Register("GET", "/livez", TierDrop)
	return NewRouteTierSampler(reg), reg
}

func TestRouteTierSampler_tierSelection(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		highVolume  float64
		standard    float64
		forceFull   bool
		spanName    string
		wantSampled bool
	}{
		// spec:observability-instrumentation/route-tier-head-sampling-of-exported-traces/agent-ingest-traffic-is-downsampled
		{"high-volume route at ratio 0 is dropped", 0, 1, false, "POST /api/events", false},
		{"high-volume route at ratio 1 is sampled", 1, 0, false, "POST /api/events", true},
		{"standard route at ratio 0 is dropped", 0, 0, false, "GET /api/hosts", false},
		{"standard route at ratio 1 is sampled", 0, 1, false, "GET /api/hosts", true},
		// spec:observability-instrumentation/route-tier-head-sampling-of-exported-traces/unclassified-routes-are-sampled-at-full-fidelity
		{"unregistered route is full fidelity even at zero ratios", 0, 0, false, "POST /api/alerts", true},
		{"unregistered GET detail read is full fidelity", 0, 0, false, "GET /api/alerts/42", true},
		// spec:observability-instrumentation/force-full-override-restores-complete-tracing/force-full-lifts-all-tiers-to-full-sampling
		{"force-full lifts high-volume to sampled", 0, 0, true, "POST /api/events", true},
		{"force-full lifts standard to sampled", 0, 0, true, "GET /api/hosts", true},
		// spec:observability-instrumentation/liveness-and-health-probe-traces-are-never-exported/probe-spans-are-dropped
		{"probe route is dropped at full ratios", 1, 1, false, "GET /livez", false},
		// spec:observability-instrumentation/liveness-and-health-probe-traces-are-never-exported/probes-stay-dropped-under-force-full
		{"probe route stays dropped under force-full", 1, 1, true, "GET /livez", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, _ := newSamplerWithPolicy()
			s.Apply(tc.highVolume, tc.standard, tc.forceFull)
			got := isSampled(s.ShouldSample(params(tc.spanName)))
			assert.Equal(t, tc.wantSampled, got)
		})
	}
}

// spec:observability-instrumentation/route-tier-head-sampling-of-exported-traces/a-sampled-parent-forces-its-children-sampled
func TestRouteTierSampler_parentBasedForcesChildrenSampled(t *testing.T) {
	t.Parallel()
	s, _ := newSamplerWithPolicy()
	s.Apply(0, 0, false) // zero ratios: a root would not be sampled
	parentBased := sdktrace.ParentBased(s)

	parentSC := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    aTraceID,
		SpanID:     trace.SpanID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), parentSC)

	// A child span whose name is not a registered route would fall to TierFull, but the sampled parent must win.
	res := parentBased.ShouldSample(sdktrace.SamplingParameters{
		ParentContext: ctx,
		TraceID:       aTraceID,
		Name:          "db.query",
		Kind:          trace.SpanKindInternal,
	})
	assert.Equal(t, sdktrace.RecordAndSample, res.Decision)

	// And an unsampled parent keeps the child unsampled (the ratio decision does not resurrect it).
	unsampledSC := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: aTraceID,
		SpanID:  trace.SpanID{0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		Remote:  true,
	})
	resUnsampled := parentBased.ShouldSample(sdktrace.SamplingParameters{
		ParentContext: trace.ContextWithSpanContext(context.Background(), unsampledSC),
		TraceID:       aTraceID,
		Name:          "POST /api/events",
		Kind:          trace.SpanKindServer,
	})
	assert.NotEqual(t, sdktrace.RecordAndSample, resUnsampled.Decision)
}

func TestRouteTierSampler_applyClampsOutOfRange(t *testing.T) {
	t.Parallel()
	s, _ := newSamplerWithPolicy()
	// high-volume clamps to 0 (never), standard clamps to 1 (always).
	s.Apply(-0.5, 2.0, false)
	assert.False(t, isSampled(s.ShouldSample(params("POST /api/events"))), "high-volume clamped to 0 must not sample")
	assert.True(t, isSampled(s.ShouldSample(params("GET /api/hosts"))), "standard clamped to 1 must sample")
	assert.Contains(t, s.Description(), "highVolume=0")
	assert.Contains(t, s.Description(), "standard=1")
}

func TestRouteTierSampler_descriptionDefaults(t *testing.T) {
	t.Parallel()
	s, _ := newSamplerWithPolicy()
	assert.Contains(t, s.Description(), "forceFull=false")
}

// TestClamp01 is the algebraic invariant: clamp01 always lands in [0,1] and is the identity inside it.
func TestClamp01(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		v := rapid.Float64().Draw(rt, "v")
		got := clamp01(v)
		require.GreaterOrEqual(t, got, 0.0)
		require.LessOrEqual(t, got, 1.0)
		if v >= 0 && v <= 1 {
			require.InDelta(t, v, got, 0)
		}
	})
}
