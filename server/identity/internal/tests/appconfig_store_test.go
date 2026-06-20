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

	require.NoError(t, store.Put(ctx, appconfig.AppConfig{ExternalURL: "https://edr.acme.com"}, nil))
	cfg, version, err := store.Get(ctx)
	require.NoError(t, err)
	assert.Equal(t, "https://edr.acme.com", cfg.ExternalURL)
	assert.Equal(t, int64(1), version)

	// Read-modify-write: a second Put bumps the version and overwrites the document.
	cfg.ExternalURL = "https://edr.acme.com:8443"
	require.NoError(t, store.Put(ctx, cfg, nil))
	got, version, err := store.Get(ctx)
	require.NoError(t, err)
	assert.Equal(t, "https://edr.acme.com:8443", got.ExternalURL)
	assert.Equal(t, int64(2), version)
}
