package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/internal/observability/tracing"
	"github.com/fleetdm/edr/server/observability/internal/tracingconfig"
	"github.com/fleetdm/edr/server/testdb/full"
)

func TestTraceSamplerStore_getReturnsSeededDefaults(t *testing.T) {
	t.Parallel()
	store := tracingconfig.New(full.Open(t))

	got, err := store.GetTraceSamplerSettings(t.Context())
	require.NoError(t, err)
	// The migration seeds the row with the sampler's compile-time defaults.
	assert.InDelta(t, tracing.DefaultHighVolumeRatio, got.HighVolumeRatio, 1e-9)
	assert.InDelta(t, tracing.DefaultStandardRatio, got.StandardRatio, 1e-9)
	assert.False(t, got.ForceFull)
}

func TestTraceSamplerStore_updateRoundTrip(t *testing.T) {
	t.Parallel()
	store := tracingconfig.New(full.Open(t))
	ctx := t.Context()

	// updatedBy nil records a non-operator write; the FK to users is exercised separately. Here we assert the value round-trip.
	require.NoError(t, store.Update(ctx, tracing.Settings{HighVolumeRatio: 0.03, StandardRatio: 0.3, ForceFull: true}, nil))

	got, err := store.GetTraceSamplerSettings(ctx)
	require.NoError(t, err)
	assert.InDelta(t, 0.03, got.HighVolumeRatio, 1e-9)
	assert.InDelta(t, 0.3, got.StandardRatio, 1e-9)
	assert.True(t, got.ForceFull)
}

// spec:observability-instrumentation/sampler-ratios-are-runtime-adjustable-without-redeploy/out-of-range-ratio-is-rejected-by-the-store
func TestTraceSamplerStore_outOfRangeRejectedByCheckConstraint(t *testing.T) {
	t.Parallel()
	store := tracingconfig.New(full.Open(t))
	ctx := t.Context()

	// The DB CHECK constraint is the backstop behind the handler's validation: a ratio above 1 is rejected at the write.
	err := store.Update(ctx, tracing.Settings{HighVolumeRatio: 2.0, StandardRatio: 0.1}, nil)
	require.Error(t, err)

	// And the stored row is unchanged (still the seeded default).
	got, getErr := store.GetTraceSamplerSettings(ctx)
	require.NoError(t, getErr)
	assert.InDelta(t, tracing.DefaultHighVolumeRatio, got.HighVolumeRatio, 1e-9)
}
