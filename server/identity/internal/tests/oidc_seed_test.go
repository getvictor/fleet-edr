package tests

import (
	"log/slog"
	"testing"
	"time"

	"github.com/fleetdm/edr/server/identity/bootstrap"
	"github.com/fleetdm/edr/server/identity/internal/ssoconfig"
	"github.com/fleetdm/edr/server/testdb/full"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fixedKey(seed byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = seed + byte(i)
	}
	return k
}

func newIdentityWithOIDCEnv(t *testing.T, db *sqlx.DB, secretKey []byte, oidc bootstrap.OIDCDeps) *bootstrap.Identity {
	t.Helper()
	id, err := bootstrap.New(t.Context(), bootstrap.Deps{
		DB:                db,
		Logger:            slog.Default(),
		SessionSigningKey: fixedKey(1),
		OIDCSecretKey:     secretKey,
		SessionAbsolute:   time.Hour,
		CleanupInterval:   time.Hour,
		OIDC:              oidc,
	})
	require.NoError(t, err)
	require.NoError(t, id.ApplySchema(t.Context()))
	return id
}

// TestBootstrap_OIDCEnvSeedsThenStoredGoverns pins the env-seeds / DB-governs precedence (issue #375): the first boot with EDR_OIDC_*
// set seeds the durable config, and a later boot with different env values leaves the stored config untouched (env is inert once a row
// exists), so an admin's UI edits are never reverted by a restart.
func TestBootstrap_OIDCEnvSeedsThenStoredGoverns(t *testing.T) {
	t.Parallel()
	db := full.Open(t)
	secretKey := fixedKey(9)

	first := newIdentityWithOIDCEnv(t, db, secretKey, bootstrap.OIDCDeps{
		Issuer: "https://first.example.com", ClientID: "cid-1", ClientSecret: "secret-1",
		RedirectURL: "https://edr.example.com/api/auth/callback", Scopes: []string{"openid", "email", "profile"},
		AllowJITProvisioning: true, DefaultRole: "analyst",
	})
	assert.True(t, first.OIDCEnabled(), "env-seeded config makes OIDC enabled at boot")

	// Read the seeded row through an independent store using the same sealing key.
	sealer, err := ssoconfig.NewSealer(secretKey)
	require.NoError(t, err)
	store := ssoconfig.New(db, sealer)

	seeded, err := store.GetDecrypted(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "https://first.example.com", seeded.Issuer)
	assert.Equal(t, "cid-1", seeded.ClientID)
	assert.Equal(t, "secret-1", seeded.ClientSecret)

	// Simulate a restart with DIFFERENT env on the same DB: the stored row must win.
	_ = newIdentityWithOIDCEnv(t, db, secretKey, bootstrap.OIDCDeps{
		Issuer: "https://second.example.com", ClientID: "cid-2", ClientSecret: "secret-2",
		RedirectURL: "https://edr.example.com/api/auth/callback", Scopes: []string{"openid"},
		AllowJITProvisioning: false, DefaultRole: "auditor",
	})

	governed, err := store.GetDecrypted(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "https://first.example.com", governed.Issuer, "env must be inert once a stored config exists")
	assert.Equal(t, "cid-1", governed.ClientID)
	assert.Equal(t, "secret-1", governed.ClientSecret)
	assert.Equal(t, int64(1), governed.Version, "inert env boot must not bump the version")
}

// TestBootstrap_noOIDCEnvLeavesUnconfigured pins that a deployment booted without EDR_OIDC_* has no stored config and reports OIDC
// disabled, so the admin configures it from the UI after a break-glass login (the login routes are still mounted).
func TestBootstrap_noOIDCEnvLeavesUnconfigured(t *testing.T) {
	t.Parallel()
	db := full.Open(t)
	secretKey := fixedKey(3)

	id := newIdentityWithOIDCEnv(t, db, secretKey, bootstrap.OIDCDeps{})
	assert.False(t, id.OIDCEnabled(), "no env config means OIDC is not enabled at boot")

	sealer, err := ssoconfig.NewSealer(secretKey)
	require.NoError(t, err)
	_, err = ssoconfig.New(db, sealer).Get(t.Context())
	require.ErrorIs(t, err, ssoconfig.ErrNotFound)
}
