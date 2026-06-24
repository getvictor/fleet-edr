package tracing

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// discard is a no-op logger so the poll loop's structured logs don't spam test output (and applyOnce never sees a nil logger,
// which StartSettingsPoller guarantees in production).
var discard = slog.New(slog.DiscardHandler)

type fakeReader struct {
	settings *Settings
	err      error
	calls    int
}

func (f *fakeReader) GetTraceSamplerSettings(context.Context) (*Settings, error) {
	f.calls++
	return f.settings, f.err
}

// spec:observability-instrumentation/sampler-ratios-are-runtime-adjustable-without-redeploy/a-ratio-change-propagates-to-running-replicas
func TestApplyOnce_appliesChangedSettings(t *testing.T) {
	t.Parallel()
	s := NewRouteTierSampler(NewRegistry())
	reader := &fakeReader{settings: &Settings{HighVolumeRatio: 0.5, StandardRatio: 0.6, ForceFull: true}}

	got := applyOnce(context.Background(), s, nil, reader, discard)

	require.NotNil(t, got)
	assert.InDelta(t, 0.5, got.HighVolumeRatio, 1e-9)
	assert.Contains(t, s.Description(), "highVolume=0.5")
	assert.Contains(t, s.Description(), "standard=0.6")
	assert.Contains(t, s.Description(), "forceFull=true")
}

func TestApplyOnce_noReapplyWhenUnchanged(t *testing.T) {
	t.Parallel()
	s := NewRouteTierSampler(NewRegistry())
	last := &Settings{HighVolumeRatio: 0.5, StandardRatio: 0.6, ForceFull: false}
	reader := &fakeReader{settings: &Settings{HighVolumeRatio: 0.5, StandardRatio: 0.6, ForceFull: false}}

	got := applyOnce(context.Background(), s, last, reader, discard)

	// Unchanged values: the same `last` pointer is returned (the early-return path that avoids a redundant atomic swap).
	assert.Same(t, last, got)
}

// spec:observability-instrumentation/sampler-ratios-are-runtime-adjustable-without-redeploy/settings-record-is-unreadable-at-startup
func TestApplyOnce_readErrorKeepsDefaults(t *testing.T) {
	t.Parallel()
	s := NewRouteTierSampler(NewRegistry())
	defaultDesc := s.Description()
	reader := &fakeReader{err: errors.New("db down")}

	got := applyOnce(context.Background(), s, nil, reader, discard)

	assert.Nil(t, got, "a read error returns last (nil at startup) so the next tick retries")
	assert.Equal(t, defaultDesc, s.Description(), "sampler keeps its compile-time defaults on a read failure")
}
