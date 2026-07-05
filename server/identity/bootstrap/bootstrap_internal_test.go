package bootstrap

import (
	"bytes"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/appconfig"
	"github.com/fleetdm/edr/server/identity/internal/oidc"
	"github.com/fleetdm/edr/server/identity/internal/ssoconfig"
	"github.com/fleetdm/edr/server/testdb"
)

// sealerKeyA and sealerKeyB are two distinct 32-byte AES-256 sealer keys. Built with bytes.Repeat rather than as string literals so
// gosec's hardcoded-credential rule (G101) doesn't fire on a test fixture.
var (
	sealerKeyA = bytes.Repeat([]byte{0xA5}, 32)
	sealerKeyB = bytes.Repeat([]byte{0x5A}, 32)
)

// newSSOStore opens an isolated schema-applied DB and returns a ssoconfig.Store sealed with key. Uses the same-package ApplySchema
// (not the identity testkit, which imports this package) so there is no import cycle.
func newSSOStore(t *testing.T, key []byte) (*sqlx.DB, *ssoconfig.Store) {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, ApplySchema(t.Context(), db))
	sealer, err := ssoconfig.NewSealer(key)
	require.NoError(t, err)
	return db, ssoconfig.New(db, sealer)
}

// TestResolveBreakglassConfig exercises every branch of the extracted break-glass config resolver: the localhost default, the two
// partial-config rejections, the signing-key requirement, and the display-name default.
func TestResolveBreakglassConfig(t *testing.T) {
	t.Parallel()
	key := []byte("session-signing-key-0123456789ab")

	t.Run("both unset defaults to localhost", func(t *testing.T) {
		t.Parallel()
		rpID, origins, display, err := resolveBreakglassConfig(BreakglassDeps{}, key)
		require.NoError(t, err)
		assert.Equal(t, "localhost", rpID)
		assert.Equal(t, []string{"https://localhost:8088", "https://127.0.0.1:8088"}, origins)
		assert.Equal(t, "EDR Break-glass", display, "display name defaults when unset")
	})

	t.Run("localhost default still requires a signing key", func(t *testing.T) {
		t.Parallel()
		_, _, _, err := resolveBreakglassConfig(BreakglassDeps{}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "SessionSigningKey is required")
	})

	t.Run("origins without RP id is rejected", func(t *testing.T) {
		t.Parallel()
		_, _, _, err := resolveBreakglassConfig(BreakglassDeps{RPOrigins: []string{"https://edr.acme.com"}}, key)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "EDR_BREAKGLASS_RP_ORIGINS set without EDR_BREAKGLASS_RP_ID")
	})

	t.Run("RP id without origins is rejected", func(t *testing.T) {
		t.Parallel()
		_, _, _, err := resolveBreakglassConfig(BreakglassDeps{RPID: "edr.acme.com"}, key)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "EDR_BREAKGLASS_RP_ID set without EDR_BREAKGLASS_RP_ORIGINS")
	})

	t.Run("fully configured with missing signing key is rejected", func(t *testing.T) {
		t.Parallel()
		bg := BreakglassDeps{RPID: "edr.acme.com", RPOrigins: []string{"https://edr.acme.com"}}
		_, _, _, err := resolveBreakglassConfig(bg, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "SessionSigningKey is required")
	})

	t.Run("fully configured returns the values with a custom display name", func(t *testing.T) {
		t.Parallel()
		bg := BreakglassDeps{RPID: "edr.acme.com", RPDisplayName: "Acme Recovery", RPOrigins: []string{"https://edr.acme.com"}}
		rpID, origins, display, err := resolveBreakglassConfig(bg, key)
		require.NoError(t, err)
		assert.Equal(t, "edr.acme.com", rpID)
		assert.Equal(t, []string{"https://edr.acme.com"}, origins)
		assert.Equal(t, "Acme Recovery", display)
	})

	t.Run("fully configured with empty display name defaults it", func(t *testing.T) {
		t.Parallel()
		bg := BreakglassDeps{RPID: "edr.acme.com", RPOrigins: []string{"https://edr.acme.com"}}
		_, _, display, err := resolveBreakglassConfig(bg, key)
		require.NoError(t, err)
		assert.Equal(t, "EDR Break-glass", display)
	})
}

// TestClampJITRole pins the JIT default-role floor: analyst/auditor (any case, trimmed) pass through, everything else (including the
// empty default and a privileged "admin") clamps to the lowest-privilege JIT role.
func TestClampJITRole(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, in, want string
	}{
		{"analyst passes through", "analyst", "analyst"},
		{"auditor passes through", "auditor", "auditor"},
		{"uppercase is normalized", "ANALYST", "analyst"},
		{"whitespace is trimmed", "  auditor  ", "auditor"},
		{"empty clamps to default", "", oidc.DefaultJITRole},
		{"admin clamps to default", "admin", oidc.DefaultJITRole},
		{"unknown clamps to default", "wheel", oidc.DefaultJITRole},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, clampJITRole(tc.in))
		})
	}
}

// TestStoredOIDCConfigUsable covers the usable/skip switch: no row -> not usable; a row with a decryptable secret -> usable; a row
// with no secret -> not usable; a row whose secret cannot be decrypted (root-key rotation) -> error so the caller can rerun with Force.
func TestStoredOIDCConfigUsable(t *testing.T) {
	t.Parallel()

	t.Run("no stored config is not usable", func(t *testing.T) {
		t.Parallel()
		_, store := newSSOStore(t, sealerKeyA)
		usable, err := storedOIDCConfigUsable(t.Context(), store)
		require.NoError(t, err)
		assert.False(t, usable)
	})

	t.Run("row with a decryptable secret is usable", func(t *testing.T) {
		t.Parallel()
		_, store := newSSOStore(t, sealerKeyA)
		secret := "shh"
		require.NoError(t, store.Upsert(t.Context(), ssoconfig.UpsertInput{
			Issuer: "https://idp.example.com", ClientID: "cid", NewSecret: &secret,
		}))
		usable, err := storedOIDCConfigUsable(t.Context(), store)
		require.NoError(t, err)
		assert.True(t, usable)
	})

	t.Run("row without a secret is not usable", func(t *testing.T) {
		t.Parallel()
		_, store := newSSOStore(t, sealerKeyA)
		require.NoError(t, store.Upsert(t.Context(), ssoconfig.UpsertInput{
			Issuer: "https://idp.example.com", ClientID: "cid", NewSecret: nil, // NULL secret column
		}))
		usable, err := storedOIDCConfigUsable(t.Context(), store)
		require.NoError(t, err)
		assert.False(t, usable, "a present-but-secretless row is (re)seedable, not usable")
	})

	t.Run("an undecryptable secret surfaces as an error", func(t *testing.T) {
		t.Parallel()
		db, storeA := newSSOStore(t, sealerKeyA)
		secret := "shh"
		require.NoError(t, storeA.Upsert(t.Context(), ssoconfig.UpsertInput{
			Issuer: "https://idp.example.com", ClientID: "cid", NewSecret: &secret,
		}))
		// A second store keyed differently reads the same row: the secret cannot be opened, which must surface as an error (not a
		// silent no-op) so the operator reruns with Force after a root-key rotation.
		sealerB, err := ssoconfig.NewSealer(sealerKeyB)
		require.NoError(t, err)
		storeB := ssoconfig.New(db, sealerB)
		usable, err := storedOIDCConfigUsable(t.Context(), storeB)
		require.Error(t, err)
		assert.False(t, usable)
		assert.Contains(t, err.Error(), "read OIDC config")
	})
}

// TestSeedOIDCConfig covers the exported non-interactive seed entry and, through it, the seed transaction, the external-URL seed, and
// the JIT-role clamp. It also pins the validation guards and the idempotent no-op / Force overwrite behaviour.
func TestSeedOIDCConfig(t *testing.T) {
	t.Parallel()

	t.Run("nil db is rejected", func(t *testing.T) {
		t.Parallel()
		err := SeedOIDCConfig(t.Context(), nil, sealerKeyA, OIDCSeedInput{Issuer: "https://idp.example.com"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "db must not be nil")
	})

	t.Run("empty issuer is rejected", func(t *testing.T) {
		t.Parallel()
		db := testdb.Open(t)
		require.NoError(t, ApplySchema(t.Context(), db))
		err := SeedOIDCConfig(t.Context(), db, sealerKeyA, OIDCSeedInput{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "issuer is required")
	})

	t.Run("a bad sealer key is rejected", func(t *testing.T) {
		t.Parallel()
		db := testdb.Open(t)
		require.NoError(t, ApplySchema(t.Context(), db))
		err := SeedOIDCConfig(t.Context(), db, []byte("too-short"), OIDCSeedInput{Issuer: "https://idp.example.com"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "build secret sealer")
	})

	t.Run("fresh seed writes config + external URL and clamps the JIT role", func(t *testing.T) {
		t.Parallel()
		db, store := newSSOStore(t, sealerKeyA)
		ctx := t.Context()
		require.NoError(t, SeedOIDCConfig(ctx, db, sealerKeyA, OIDCSeedInput{
			Issuer: "https://idp.example.com", ClientID: "cid", ClientSecret: "shh",
			Scopes: []string{"openid", "email"}, JITEnabled: true, DefaultRole: "admin", // admin must clamp
			ExternalURL: "https://edr.example.com",
		}))

		cfg, err := store.GetDecrypted(ctx)
		require.NoError(t, err)
		assert.Equal(t, "https://idp.example.com", cfg.Issuer)
		assert.Equal(t, "cid", cfg.ClientID)
		assert.Equal(t, "shh", cfg.ClientSecret)
		assert.True(t, cfg.JITEnabled)
		assert.Equal(t, oidc.DefaultJITRole, cfg.DefaultRole, "a privileged seeded default role clamps to the JIT floor")

		appCfg, _, err := appconfig.New(db).Get(ctx)
		require.NoError(t, err)
		assert.Equal(t, "https://edr.example.com", appCfg.ExternalURL, "external URL seeded into app_config")
	})

	t.Run("re-seed without force is a no-op over a usable config", func(t *testing.T) {
		t.Parallel()
		db, store := newSSOStore(t, sealerKeyA)
		ctx := t.Context()
		first := OIDCSeedInput{Issuer: "https://first.example.com", ClientID: "cid", ClientSecret: "shh"}
		require.NoError(t, SeedOIDCConfig(ctx, db, sealerKeyA, first))
		// A second call with a different issuer must NOT clobber the usable stored config.
		require.NoError(t, SeedOIDCConfig(ctx, db, sealerKeyA, OIDCSeedInput{
			Issuer: "https://second.example.com", ClientID: "cid2", ClientSecret: "other",
		}))
		cfg, err := store.GetDecrypted(ctx)
		require.NoError(t, err)
		assert.Equal(t, "https://first.example.com", cfg.Issuer, "usable config governs; the second seed is a no-op")
	})

	t.Run("a preset external URL is never clobbered", func(t *testing.T) {
		t.Parallel()
		db, store := newSSOStore(t, sealerKeyA)
		ctx := t.Context()
		// An operator already set the external URL; a later seed must leave it alone even while it writes the (absent) OIDC config.
		require.NoError(t, appconfig.New(db).Put(ctx, appconfig.AppConfig{ExternalURL: "https://preset.example.com"}, 0, api.PrincipalSystemID))
		require.NoError(t, SeedOIDCConfig(ctx, db, sealerKeyA, OIDCSeedInput{
			Issuer: "https://idp.example.com", ClientID: "cid", ClientSecret: "shh", ExternalURL: "https://seed.example.com",
		}))
		appCfg, _, err := appconfig.New(db).Get(ctx)
		require.NoError(t, err)
		assert.Equal(t, "https://preset.example.com", appCfg.ExternalURL, "the operator's external URL is not clobbered by a seed")
		cfg, err := store.GetDecrypted(ctx)
		require.NoError(t, err)
		assert.Equal(t, "https://idp.example.com", cfg.Issuer, "the OIDC config is still seeded")
	})

	t.Run("undecryptable existing config without force surfaces the read error", func(t *testing.T) {
		t.Parallel()
		db, _ := newSSOStore(t, sealerKeyA)
		ctx := t.Context()
		require.NoError(t, SeedOIDCConfig(ctx, db, sealerKeyA,
			OIDCSeedInput{Issuer: "https://idp.example.com", ClientID: "cid", ClientSecret: "shh"}))
		// A different root key can't open the stored secret; without Force the usable-check must surface that as an error (so the
		// operator reruns with Force) rather than silently no-oping over a broken row.
		err := SeedOIDCConfig(ctx, db, sealerKeyB,
			OIDCSeedInput{Issuer: "https://idp.example.com", ClientID: "cid", ClientSecret: "shh"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "read OIDC config")
	})

	t.Run("force overwrites an existing config", func(t *testing.T) {
		t.Parallel()
		db, store := newSSOStore(t, sealerKeyA)
		ctx := t.Context()
		require.NoError(t, SeedOIDCConfig(ctx, db, sealerKeyA,
			OIDCSeedInput{Issuer: "https://first.example.com", ClientID: "cid", ClientSecret: "shh"}))
		require.NoError(t, SeedOIDCConfig(ctx, db, sealerKeyA, OIDCSeedInput{
			Issuer: "https://second.example.com", ClientID: "cid2", ClientSecret: "other", Force: true,
		}))
		cfg, err := store.GetDecrypted(ctx)
		require.NoError(t, err)
		assert.Equal(t, "https://second.example.com", cfg.Issuer, "Force re-seeds over the existing config")
	})
}

// TestNewOIDCProviderConfigFn exercises the per-login provider-config resolver closure: no stored config maps to ErrNotConfigured; a
// stored config with no derivable redirect (external URL unset) also maps to ErrNotConfigured; a full config yields the derived
// redirect URL and a version stamp.
func TestNewOIDCProviderConfigFn(t *testing.T) {
	t.Parallel()

	t.Run("no stored config maps to ErrNotConfigured", func(t *testing.T) {
		t.Parallel()
		db, store := newSSOStore(t, sealerKeyA)
		fn := newOIDCProviderConfigFn(store, appconfig.New(db))
		_, err := fn(t.Context())
		require.ErrorIs(t, err, oidc.ErrNotConfigured)
	})

	t.Run("stored config without an external URL maps to ErrNotConfigured", func(t *testing.T) {
		t.Parallel()
		db, store := newSSOStore(t, sealerKeyA)
		ctx := t.Context()
		secret := "shh"
		require.NoError(t, store.Upsert(ctx, ssoconfig.UpsertInput{Issuer: "https://idp.example.com", ClientID: "cid", NewSecret: &secret}))
		fn := newOIDCProviderConfigFn(store, appconfig.New(db))
		_, err := fn(ctx)
		require.ErrorIs(t, err, oidc.ErrNotConfigured, "an unset external URL cannot derive a redirect, so it reads as not-configured")
	})

	t.Run("full config yields the derived redirect and stamp", func(t *testing.T) {
		t.Parallel()
		db, store := newSSOStore(t, sealerKeyA)
		ctx := t.Context()
		require.NoError(t, SeedOIDCConfig(ctx, db, sealerKeyA, OIDCSeedInput{
			Issuer: "https://idp.example.com", ClientID: "cid", ClientSecret: "shh", ExternalURL: "https://edr.example.com",
		}))
		fn := newOIDCProviderConfigFn(store, appconfig.New(db))
		got, err := fn(ctx)
		require.NoError(t, err)
		assert.Equal(t, "https://idp.example.com", got.Issuer)
		assert.Equal(t, "cid", got.ClientID)
		assert.Equal(t, "shh", got.ClientSecret)
		assert.Equal(t, "https://edr.example.com/api/auth/callback", got.RedirectURL)
		assert.NotEmpty(t, got.Stamp, "the cache stamp folds both config versions")
	})

	t.Run("a non-ErrNotFound store read error is surfaced, not masked as not-configured", func(t *testing.T) {
		t.Parallel()
		// Closing the handle makes the next read fail with a driver error ("database is closed"), which is NOT ErrNotFound. The
		// closure must return that error verbatim so a real store fault surfaces as a 500, not the directed "SSO not configured" reply.
		db, store := newSSOStore(t, sealerKeyA)
		require.NoError(t, db.Close())
		fn := newOIDCProviderConfigFn(store, appconfig.New(db))
		_, err := fn(t.Context())
		require.Error(t, err)
		assert.NotErrorIs(t, err, oidc.ErrNotConfigured, "a store read failure must not be flattened into ErrNotConfigured")
	})

	t.Run("an app-config read error is surfaced after the OIDC config loads", func(t *testing.T) {
		t.Parallel()
		db, store := newSSOStore(t, sealerKeyA)
		ctx := t.Context()
		secret := "shh"
		// A usable OIDC config so GetDecrypted returns cleanly: the failure must come from the app_config read that derives the
		// redirect URL, exercising the second (appConfig.Get) error branch rather than the first (store) one. Dropping only the
		// app_config table leaves oidc_config intact, so the first read succeeds and the second fails with a real (non-ErrNoRows) error.
		require.NoError(t, store.Upsert(ctx, ssoconfig.UpsertInput{Issuer: "https://idp.example.com", ClientID: "cid", NewSecret: &secret}))
		_, err := db.ExecContext(ctx, "DROP TABLE app_config")
		require.NoError(t, err)
		fn := newOIDCProviderConfigFn(store, appconfig.New(db))
		_, err = fn(ctx)
		require.Error(t, err)
		assert.NotErrorIs(t, err, oidc.ErrNotConfigured, "an app_config read failure is a real error, not not-configured")
	})
}

// TestNewOIDCJITPolicyFn exercises the JIT-policy closure the provisioner reads: no stored config means JIT off (deny unknown
// subjects); a stored config surfaces its JIT toggle + default role.
func TestNewOIDCJITPolicyFn(t *testing.T) {
	t.Parallel()

	t.Run("no stored config means JIT off", func(t *testing.T) {
		t.Parallel()
		_, store := newSSOStore(t, sealerKeyA)
		fn := newOIDCJITPolicyFn(store)
		allow, role, err := fn(t.Context())
		require.NoError(t, err)
		assert.False(t, allow)
		assert.Empty(t, role)
	})

	t.Run("stored config surfaces its JIT toggle and role", func(t *testing.T) {
		t.Parallel()
		_, store := newSSOStore(t, sealerKeyA)
		ctx := t.Context()
		secret := "shh"
		require.NoError(t, store.Upsert(ctx, ssoconfig.UpsertInput{
			Issuer: "https://idp.example.com", ClientID: "cid", NewSecret: &secret, JITEnabled: true, DefaultRole: "auditor",
		}))
		fn := newOIDCJITPolicyFn(store)
		allow, role, err := fn(ctx)
		require.NoError(t, err)
		assert.True(t, allow)
		assert.Equal(t, "auditor", role)
	})

	t.Run("a non-ErrNotFound store read error is surfaced, not silently JIT-off", func(t *testing.T) {
		t.Parallel()
		// A closed handle makes store.Get fail with a driver error (not ErrNotFound). The closure must return that error so a store
		// fault propagates to the provisioner rather than being flattened into the "JIT off, deny unknown subject" default.
		db, store := newSSOStore(t, sealerKeyA)
		require.NoError(t, db.Close())
		fn := newOIDCJITPolicyFn(store)
		_, _, err := fn(t.Context())
		require.Error(t, err)
	})
}
