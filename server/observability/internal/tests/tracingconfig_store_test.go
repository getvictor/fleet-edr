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

	got, version, err := store.Get(t.Context())
	require.NoError(t, err)
	// The migration seeds the row with the sampler's compile-time defaults at version 1.
	assert.InDelta(t, tracing.DefaultHighVolumeRatio, got.HighVolumeRatio, 1e-9)
	assert.InDelta(t, tracing.DefaultStandardRatio, got.StandardRatio, 1e-9)
	assert.False(t, got.ForceFull)
	assert.Equal(t, int64(1), version)
}

func TestTraceSamplerStore_updateRoundTripBumpsVersion(t *testing.T) {
	t.Parallel()
	store := tracingconfig.New(full.Open(t))
	ctx := t.Context()

	_, version, err := store.Get(ctx)
	require.NoError(t, err)
	// updatedBy nil records a non-operator write; the value round-trip + version bump are what we assert here.
	require.NoError(t, store.Update(ctx, tracing.Settings{HighVolumeRatio: 0.03, StandardRatio: 0.3, ForceFull: true}, version, ""))

	got, newVersion, err := store.Get(ctx)
	require.NoError(t, err)
	assert.InDelta(t, 0.03, got.HighVolumeRatio, 1e-9)
	assert.InDelta(t, 0.3, got.StandardRatio, 1e-9)
	assert.True(t, got.ForceFull)
	assert.Equal(t, version+1, newVersion)
}

// spec:observability-instrumentation/sampler-ratios-are-runtime-adjustable-without-redeploy/out-of-range-ratio-is-rejected-by-the-store
func TestTraceSamplerStore_outOfRangeRejectedByCheckConstraint(t *testing.T) {
	t.Parallel()
	store := tracingconfig.New(full.Open(t))
	ctx := t.Context()

	_, version, err := store.Get(ctx)
	require.NoError(t, err)
	// The DB CHECK constraint is the backstop behind the handler's validation: a ratio above 1 is rejected at the write.
	require.Error(t, store.Update(ctx, tracing.Settings{HighVolumeRatio: 2.0, StandardRatio: 0.1}, version, ""))

	// And the stored row is unchanged (still the seeded default).
	got, _, getErr := store.Get(ctx)
	require.NoError(t, getErr)
	assert.InDelta(t, tracing.DefaultHighVolumeRatio, got.HighVolumeRatio, 1e-9)
}

func TestTraceSamplerStore_staleVersionConflicts(t *testing.T) {
	t.Parallel()
	store := tracingconfig.New(full.Open(t))
	ctx := t.Context()

	_, version, err := store.Get(ctx)
	require.NoError(t, err)
	// First writer holding the current version succeeds and bumps it.
	require.NoError(t, store.Update(ctx, tracing.Settings{HighVolumeRatio: 0.02, StandardRatio: 0.2}, version, ""))
	// A second writer still holding the now-stale version is rejected (lost-update prevented).
	err = store.Update(ctx, tracing.Settings{HighVolumeRatio: 0.04, StandardRatio: 0.4}, version, "")
	require.ErrorIs(t, err, tracingconfig.ErrVersionConflict)
}

func TestTraceSamplerStore_getTraceSamplerSettingsDropsVersion(t *testing.T) {
	t.Parallel()
	store := tracingconfig.New(full.Open(t))
	// The reader surface the poller uses returns just the settings.
	got, err := store.GetTraceSamplerSettings(t.Context())
	require.NoError(t, err)
	assert.InDelta(t, tracing.DefaultHighVolumeRatio, got.HighVolumeRatio, 1e-9)
}

func TestTraceSamplerStore_missingRowSelfHeals(t *testing.T) {
	t.Parallel()
	db := full.Open(t)
	store := tracingconfig.New(db)
	ctx := t.Context()
	_, err := db.ExecContext(ctx, "DELETE FROM trace_sampler_settings")
	require.NoError(t, err)

	// Get on a missing row returns built-in defaults at version 0 (self-heal, not an error).
	got, version, err := store.Get(ctx)
	require.NoError(t, err)
	assert.InDelta(t, tracing.DefaultHighVolumeRatio, got.HighVolumeRatio, 1e-9)
	assert.Equal(t, int64(0), version)

	// Update with version 0 re-inserts the singleton rather than failing on the absent row.
	require.NoError(t, store.Update(ctx, tracing.Settings{HighVolumeRatio: 0.07, StandardRatio: 0.7}, 0, ""))
	got2, _, err := store.Get(ctx)
	require.NoError(t, err)
	assert.InDelta(t, 0.07, got2.HighVolumeRatio, 1e-9)
}
