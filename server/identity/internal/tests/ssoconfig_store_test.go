package tests

import (
	"testing"

	"github.com/fleetdm/edr/server/identity/internal/ssoconfig"
	"github.com/fleetdm/edr/server/testdb/full"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newSSOStore(t *testing.T) *ssoconfig.Store {
	t.Helper()
	db := full.Open(t)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 7)
	}
	sealer, err := ssoconfig.NewSealer(key)
	require.NoError(t, err)
	return ssoconfig.New(db, sealer)
}

func strptr(s string) *string { return &s }

func TestSSOConfigStore_getOnEmptyIsNotFound(t *testing.T) {
	t.Parallel()
	store := newSSOStore(t)

	_, err := store.Get(t.Context())
	require.ErrorIs(t, err, ssoconfig.ErrNotFound)

	_, err = store.GetDecrypted(t.Context())
	require.ErrorIs(t, err, ssoconfig.ErrNotFound)
}

func TestSSOConfigStore_insertReadAndSecretIsWriteOnly(t *testing.T) {
	t.Parallel()
	store := newSSOStore(t)
	ctx := t.Context()

	require.NoError(t, store.Upsert(ctx, ssoconfig.UpsertInput{
		Issuer:      "https://acme.okta.com",
		ClientID:    "0oa8x2k4mWq1ZpL5d7",
		NewSecret:   strptr("top-secret-value"),
		ExternalURL: "https://edr.acme.com/api/auth/callback",
		Scopes:      []string{"openid", "email", "profile"},
		JITEnabled:  true,
		DefaultRole: "analyst",
	}))

	// Get never carries the secret, but reports its presence.
	got, err := store.Get(ctx)
	require.NoError(t, err)
	assert.Equal(t, "https://acme.okta.com", got.Issuer)
	assert.Equal(t, "0oa8x2k4mWq1ZpL5d7", got.ClientID)
	assert.Equal(t, []string{"openid", "email", "profile"}, got.Scopes)
	assert.True(t, got.JITEnabled)
	assert.Equal(t, "analyst", got.DefaultRole)
	assert.True(t, got.HasSecret)
	assert.Empty(t, got.ClientSecret, "Get must never expose the plaintext secret")
	assert.Equal(t, int64(1), got.Version)

	// GetDecrypted (resolver path) opens the secret.
	dec, err := store.GetDecrypted(ctx)
	require.NoError(t, err)
	assert.Equal(t, "top-secret-value", dec.ClientSecret)
}

func TestSSOConfigStore_omittedSecretIsPreservedAndVersionBumps(t *testing.T) {
	t.Parallel()
	store := newSSOStore(t)
	ctx := t.Context()

	require.NoError(t, store.Upsert(ctx, ssoconfig.UpsertInput{
		Issuer: "https://one.example.com", ClientID: "cid-1", NewSecret: strptr("original-secret"),
		ExternalURL: "https://edr.example.com/cb", Scopes: []string{"openid"}, JITEnabled: true, DefaultRole: "analyst",
	}))

	// Update everything EXCEPT the secret (NewSecret nil): the stored secret must survive.
	require.NoError(t, store.Upsert(ctx, ssoconfig.UpsertInput{
		Issuer: "https://two.example.com", ClientID: "cid-2", NewSecret: nil,
		ExternalURL: "https://edr.example.com/cb2", Scopes: []string{"openid", "email"}, JITEnabled: false, DefaultRole: "auditor",
	}))

	dec, err := store.GetDecrypted(ctx)
	require.NoError(t, err)
	assert.Equal(t, "https://two.example.com", dec.Issuer)
	assert.Equal(t, "cid-2", dec.ClientID)
	assert.False(t, dec.JITEnabled)
	assert.Equal(t, "auditor", dec.DefaultRole)
	assert.Equal(t, "original-secret", dec.ClientSecret, "omitting NewSecret must preserve the stored secret")
	assert.Equal(t, int64(2), dec.Version, "config_version must increment on update")
}

func TestSSOConfigStore_rotateSecret(t *testing.T) {
	t.Parallel()
	store := newSSOStore(t)
	ctx := t.Context()

	require.NoError(t, store.Upsert(ctx, ssoconfig.UpsertInput{
		Issuer: "https://idp.example.com", ClientID: "cid", NewSecret: strptr("secret-v1"),
		ExternalURL: "https://edr.example.com/cb", Scopes: []string{"openid"}, JITEnabled: true, DefaultRole: "analyst",
	}))
	require.NoError(t, store.Upsert(ctx, ssoconfig.UpsertInput{
		Issuer: "https://idp.example.com", ClientID: "cid", NewSecret: strptr("secret-v2"),
		ExternalURL: "https://edr.example.com/cb", Scopes: []string{"openid"}, JITEnabled: true, DefaultRole: "analyst",
	}))

	dec, err := store.GetDecrypted(ctx)
	require.NoError(t, err)
	assert.Equal(t, "secret-v2", dec.ClientSecret)
}
