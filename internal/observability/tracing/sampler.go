package tracing

import (
	"fmt"
	"sync/atomic"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Default sampling ratios. These match the seeded trace_sampler_settings row so a freshly started replica samples the same as one
// that has already polled the DB. High-volume agent traffic is cut to 1%, operator/UI reads to 10%; everything in TierFull stays at
// 100%. Both are tunable at runtime via the settings API, so these are starting points, not ceilings.
const (
	DefaultHighVolumeRatio = 0.01
	DefaultStandardRatio   = 0.1
)

// RouteTierSampler implements sdktrace.Sampler. The configured ratios live in an atomic.Pointer so StartSettingsPoller can swap them
// under a hot reader without locking. Tier classification is delegated to the Registry passed at construction.
//
// Wrap it in sdktrace.ParentBased at the provider so a sampled parent forces its children sampled (otherwise child spans, whose names
// are not in the registry, would each independently fall to TierFull and export even when the root HTTP span was dropped).
type RouteTierSampler struct {
	state    atomic.Pointer[samplerState]
	registry *Registry
}

type samplerState struct {
	highVolume sdktrace.Sampler
	standard   sdktrace.Sampler
	full       sdktrace.Sampler
	drop       sdktrace.Sampler
	// highVolumeRatio + standardRatio are the clamped ratios the two ratio samplers were built from, retained for Description.
	highVolumeRatio float64
	standardRatio   float64
	forceFull       bool
}

// NewRouteTierSampler returns a sampler initialized with the default ratios and force_full=false. The poller (if running) overwrites
// these on its first tick once it reads the DB row. Panics if registry is nil.
func NewRouteTierSampler(registry *Registry) *RouteTierSampler {
	if registry == nil {
		panic("tracing.NewRouteTierSampler: registry is required")
	}
	s := &RouteTierSampler{registry: registry}
	s.state.Store(buildState(DefaultHighVolumeRatio, DefaultStandardRatio, false))
	return s
}

// Apply replaces the sampler's state atomically. Out-of-range ratios are clamped to [0,1] as a defensive backstop; the DB CHECK
// constraints and the PATCH handler validation reject them earlier.
func (s *RouteTierSampler) Apply(highVolume, standard float64, forceFull bool) {
	s.state.Store(buildState(clamp01(highVolume), clamp01(standard), forceFull))
}

func clamp01(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	default:
		return v
	}
}

func buildState(highVolume, standard float64, forceFull bool) *samplerState {
	return &samplerState{
		highVolume:      sdktrace.TraceIDRatioBased(highVolume),
		standard:        sdktrace.TraceIDRatioBased(standard),
		full:            sdktrace.AlwaysSample(),
		drop:            sdktrace.NeverSample(),
		highVolumeRatio: highVolume,
		standardRatio:   standard,
		forceFull:       forceFull,
	}
}

// ShouldSample implements sdktrace.Sampler. TierDrop is checked first so probes are dropped even under force_full. For every other
// tier, force_full lifts sampling to 100%; otherwise the tier's configured ratio applies. Unregistered spans fall to TierFull (100%).
func (s *RouteTierSampler) ShouldSample(p sdktrace.SamplingParameters) sdktrace.SamplingResult {
	st := s.state.Load()
	tier := s.registry.Lookup(p.Name)
	if tier == TierDrop {
		return st.drop.ShouldSample(p)
	}
	if st.forceFull {
		return st.full.ShouldSample(p)
	}
	switch tier {
	case TierHighVolume:
		return st.highVolume.ShouldSample(p)
	case TierStandard:
		return st.standard.ShouldSample(p)
	case TierFull:
		return st.full.ShouldSample(p)
	case TierDrop:
		// Unreachable (handled before the force_full branch); listed so the switch is exhaustive over Tier.
		return st.drop.ShouldSample(p)
	}
	// Compiler-required terminator: a switch over typed constants is not a terminating statement. A future tier with no case falls
	// back to full fidelity rather than silently dropping.
	return st.full.ShouldSample(p)
}

// Description implements sdktrace.Sampler. Used by the SDK for diagnostic logging.
func (s *RouteTierSampler) Description() string {
	st := s.state.Load()
	return fmt.Sprintf("RouteTierSampler{highVolume=%g,standard=%g,forceFull=%t}",
		st.highVolumeRatio, st.standardRatio, st.forceFull)
}
