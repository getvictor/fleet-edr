package tests

import (
	"testing"

	"github.com/fleetdm/edr/server/identity/internal/appconfig"
	"github.com/fleetdm/edr/server/testdb/full"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppConfigStore_emptyReturnsZeroValue(t *testing.T) {
	t.Parallel()
	store := appconfig.New(full.Open(t))
	cfg, version, err := store.Get(t.Context())
	require.NoError(t, err)
	assert.Equal(t, appconfig.AppConfig{}, cfg, "a deployment with no row reads a zero-value document, not an error")
	assert.Equal(t, int64(0), version)
}

func TestAppConfigStore_putGetRoundTripAndVersionBumps(t *testing.T) {
	t.Parallel()
	store := appconfig.New(full.Open(t))
	ctx := t.Context()

	// First write: no row yet, so expectedVersion 0 inserts the singleton.
	require.NoError(t, store.Put(ctx, appconfig.AppConfig{ExternalURL: "https://edr.acme.com"}, 0, nil))
	cfg, version, err := store.Get(ctx)
	require.NoError(t, err)
	assert.Equal(t, "https://edr.acme.com", cfg.ExternalURL)
	assert.Equal(t, int64(1), version)

	// Read-modify-write with the read version: the OCC update bumps the version and overwrites the document.
	cfg.ExternalURL = "https://edr.acme.com:8443"
	require.NoError(t, store.Put(ctx, cfg, version, nil))
	got, version, err := store.Get(ctx)
	require.NoError(t, err)
	assert.Equal(t, "https://edr.acme.com:8443", got.ExternalURL)
	assert.Equal(t, int64(2), version)
}

func TestAppConfigStore_putWithStaleVersionConflicts(t *testing.T) {
	t.Parallel()
	store := appconfig.New(full.Open(t))
	ctx := t.Context()

	require.NoError(t, store.Put(ctx, appconfig.AppConfig{ExternalURL: "https://a"}, 0, nil))
	_, version, err := store.Get(ctx)
	require.NoError(t, err)

	// A writer holding the current version succeeds and bumps it.
	require.NoError(t, store.Put(ctx, appconfig.AppConfig{ExternalURL: "https://b"}, version, nil))
	// A second writer still holding the now-stale version is rejected (lost-update prevented).
	err = store.Put(ctx, appconfig.AppConfig{ExternalURL: "https://c"}, version, nil)
	require.ErrorIs(t, err, appconfig.ErrVersionConflict)
}
