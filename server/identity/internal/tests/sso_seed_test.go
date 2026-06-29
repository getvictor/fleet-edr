package tests

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fleetdm/edr/server/identity/bootstrap"
	"github.com/fleetdm/edr/server/identity/internal/appconfig"
	"github.com/fleetdm/edr/server/identity/internal/ssoconfig"
	"github.com/fleetdm/edr/server/testdb/full"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedKey returns a deterministic 32-byte key so a test can build a sealer and re-open the same sealed config across a simulated
// restart. The seed byte distinguishes the signing key from the OIDC secret key within one test.
func fixedKey(seed byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = seed + byte(i)
	}
	return k
}

// TestSeedOIDCConfig covers the programmatic seed seam (issue #512) the demo/QA stacks use in place of the removed server-side
// EDR_OIDC_* ingestion: a fresh deployment has no config, a seed makes OIDC enabled and survives a restart, a re-seed is inert, and a
// forced re-seed overwrites (the e2e harness re-points the JIT toggle this way).
func TestSeedOIDCConfig(t *testing.T) {
	t.Parallel()

	// spec:sso-configuration/oidc-configuration-is-stored-durably-and-is-the-runtime-source-of-truth/stored-configuration-survives-a-restart
	t.Run("seed then restart serves the stored config", func(t *testing.T) {
		t.Parallel()
		idp := oidcDiscoveryServer(t)
		db := full.Open(t)
		secretKey := fixedKey(9)

		first, err := bootstrap.New(t.Context(), bootstrap.Deps{
			DB: db, Logger: slog.Default(), SessionSigningKey: fixedKey(1), OIDCSecretKey: secretKey,
			SessionAbsolute: time.Hour, CleanupInterval: time.Hour, OIDC: bootstrap.OIDCDeps{HTTPClient: idp.Client()},
		})
		require.NoError(t, err)
		require.NoError(t, first.ApplySchema(t.Context()))
		require.False(t, first.OIDCEnabled(t.Context()), "no stored config yet, so OIDC is not enabled")

		require.NoError(t, bootstrap.SeedOIDCConfig(t.Context(), db, secretKey, bootstrap.OIDCSeedInput{
			Issuer: idp.URL, ClientID: "cid-1", ClientSecret: "secret-1",
			Scopes: []string{"openid", "email", "profile"}, JITEnabled: true, DefaultRole: "analyst",
			ExternalURL: "https://edr.example.com",
		}))
		require.True(t, first.OIDCEnabled(t.Context()), "a seeded config makes OIDC enabled with no restart")

		// Simulate a restart with NO OIDC env: a fresh identity over the same DB must still serve the stored config.
		second, err := bootstrap.New(t.Context(), bootstrap.Deps{
			DB: db, Logger: slog.Default(), SessionSigningKey: fixedKey(1), OIDCSecretKey: secretKey,
			SessionAbsolute: time.Hour, CleanupInterval: time.Hour, OIDC: bootstrap.OIDCDeps{HTTPClient: idp.Client()},
		})
		require.NoError(t, err)
		require.NoError(t, second.ApplySchema(t.Context()))
		require.True(t, second.OIDCEnabled(t.Context()), "the stored config survives a restart")

		// The login flow on the restarted identity resolves the stored provider, proving the store (not any boot-time env) governs.
		mux := http.NewServeMux()
		second.RegisterPublicRoutes(mux)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/auth/login", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		require.Equal(t, http.StatusFound, w.Code)
		assert.Contains(t, w.Header().Get("Location"), idp.URL+"/auth")

		// The external URL was recovered into the appconfig document, so the derived redirect is correct.
		appCfg, _, err := appconfig.New(db).Get(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "https://edr.example.com", appCfg.ExternalURL)
	})

	t.Run("re-seed without force is inert", func(t *testing.T) {
		t.Parallel()
		db := full.Open(t)
		secretKey := fixedKey(13)
		require.NoError(t, bootstrap.ApplySchema(t.Context(), db))

		seed := func(issuer, clientID, secret string, force bool) error {
			return bootstrap.SeedOIDCConfig(t.Context(), db, secretKey, bootstrap.OIDCSeedInput{
				Issuer: issuer, ClientID: clientID, ClientSecret: secret,
				Scopes: []string{"openid"}, JITEnabled: true, DefaultRole: "analyst", Force: force,
			})
		}
		require.NoError(t, seed("https://first.example.com", "cid-1", "secret-1", false))
		require.NoError(t, seed("https://second.example.com", "cid-2", "secret-2", false)) // inert

		sealer, err := ssoconfig.NewSealer(secretKey)
		require.NoError(t, err)
		got, err := ssoconfig.New(db, sealer).GetDecrypted(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "https://first.example.com", got.Issuer, "a second seed without force must not overwrite")
		assert.Equal(t, "cid-1", got.ClientID)
		assert.Equal(t, "secret-1", got.ClientSecret)
		assert.Equal(t, int64(1), got.Version, "an inert seed must not bump the version")
	})

	t.Run("force overwrites the stored config", func(t *testing.T) {
		t.Parallel()
		db := full.Open(t)
		secretKey := fixedKey(17)
		require.NoError(t, bootstrap.ApplySchema(t.Context(), db))

		require.NoError(t, bootstrap.SeedOIDCConfig(t.Context(), db, secretKey, bootstrap.OIDCSeedInput{
			Issuer: "https://idp.example.com", ClientID: "cid", ClientSecret: "s",
			Scopes: []string{"openid"}, JITEnabled: true, DefaultRole: "analyst",
		}))
		require.NoError(t, bootstrap.SeedOIDCConfig(t.Context(), db, secretKey, bootstrap.OIDCSeedInput{
			Issuer: "https://idp.example.com", ClientID: "cid", ClientSecret: "s",
			Scopes: []string{"openid"}, JITEnabled: false, DefaultRole: "auditor", Force: true,
		}))

		sealer, err := ssoconfig.NewSealer(secretKey)
		require.NoError(t, err)
		got, err := ssoconfig.New(db, sealer).Get(t.Context())
		require.NoError(t, err)
		assert.False(t, got.JITEnabled, "force re-seed must apply the new JIT toggle")
		assert.Equal(t, "auditor", got.DefaultRole)
	})

	t.Run("privileged default role is clamped to the JIT floor", func(t *testing.T) {
		t.Parallel()
		db := full.Open(t)
		secretKey := fixedKey(23)
		require.NoError(t, bootstrap.ApplySchema(t.Context(), db))

		// A non-interactive caller must not be able to seed default_role=admin and have the OIDC provisioner auto-bind first-time SSO
		// users to a privileged role; the seam clamps anything outside {analyst, auditor} to the lowest-privilege JIT role.
		require.NoError(t, bootstrap.SeedOIDCConfig(t.Context(), db, secretKey, bootstrap.OIDCSeedInput{
			Issuer: "https://idp.example.com", ClientID: "cid", ClientSecret: "s",
			Scopes: []string{"openid"}, JITEnabled: true, DefaultRole: "admin",
		}))

		sealer, err := ssoconfig.NewSealer(secretKey)
		require.NoError(t, err)
		got, err := ssoconfig.New(db, sealer).Get(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "analyst", got.DefaultRole, "default_role=admin must be clamped to analyst")
	})

	t.Run("undecryptable row errors without force and is repaired with force", func(t *testing.T) {
		t.Parallel()
		db := full.Open(t)
		keyA := fixedKey(29)
		keyB := fixedKey(31) // a different sealer key, e.g. after an EDR_SECRET_KEY rotation
		require.NoError(t, bootstrap.ApplySchema(t.Context(), db))

		seed := func(key []byte, force bool) error {
			return bootstrap.SeedOIDCConfig(t.Context(), db, key, bootstrap.OIDCSeedInput{
				Issuer: "https://idp.example.com", ClientID: "cid", ClientSecret: "s",
				Scopes: []string{"openid"}, JITEnabled: true, DefaultRole: "analyst", Force: force,
			})
		}
		require.NoError(t, seed(keyA, false)) // row sealed with key A

		// A non-force re-seed with a different key must NOT silently no-op over a row it cannot decrypt; it errors instead.
		require.Error(t, seed(keyB, false), "an undecryptable existing config must surface an error, not a silent no-op")

		// Force overwrites the unreadable row, repairing SSO; the row now decrypts with key B.
		require.NoError(t, seed(keyB, true))
		sealerB, err := ssoconfig.NewSealer(keyB)
		require.NoError(t, err)
		_, err = ssoconfig.New(db, sealerB).GetDecrypted(t.Context())
		require.NoError(t, err, "force re-seed must leave a config decryptable with the new key")
	})

	t.Run("secretless row is re-seeded, not skipped", func(t *testing.T) {
		t.Parallel()
		db := full.Open(t)
		secretKey := fixedKey(37)
		require.NoError(t, bootstrap.ApplySchema(t.Context(), db))

		// A row that decrypts but carries no client secret is not usable (login token exchange needs the secret). A later non-force
		// seed must repair it rather than no-op over it.
		require.NoError(t, bootstrap.SeedOIDCConfig(t.Context(), db, secretKey, bootstrap.OIDCSeedInput{
			Issuer: "https://idp.example.com", ClientID: "cid", ClientSecret: "",
			Scopes: []string{"openid"}, JITEnabled: true, DefaultRole: "analyst",
		}))
		require.NoError(t, bootstrap.SeedOIDCConfig(t.Context(), db, secretKey, bootstrap.OIDCSeedInput{
			Issuer: "https://idp.example.com", ClientID: "cid", ClientSecret: "real-secret",
			Scopes: []string{"openid"}, JITEnabled: true, DefaultRole: "analyst",
		}))

		sealer, err := ssoconfig.NewSealer(secretKey)
		require.NoError(t, err)
		got, err := ssoconfig.New(db, sealer).GetDecrypted(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "real-secret", got.ClientSecret, "a non-force seed must repair a secretless row")
	})

	t.Run("OIDCEnabled requires a decryptable secret and a derivable redirect", func(t *testing.T) {
		t.Parallel()
		db := full.Open(t)
		secretKey := fixedKey(41)
		id, err := bootstrap.New(t.Context(), bootstrap.Deps{
			DB: db, Logger: slog.Default(), SessionSigningKey: fixedKey(1), OIDCSecretKey: secretKey,
			SessionAbsolute: time.Hour, CleanupInterval: time.Hour, OIDC: bootstrap.OIDCDeps{},
		})
		require.NoError(t, err)
		require.NoError(t, id.ApplySchema(t.Context()))
		assert.False(t, id.OIDCEnabled(t.Context()), "no stored config yet")

		// A row that decrypts but has no client secret is not usable; OIDCEnabled must stay false.
		require.NoError(t, bootstrap.SeedOIDCConfig(t.Context(), db, secretKey, bootstrap.OIDCSeedInput{
			Issuer: "https://idp.example.com", ClientID: "cid", ClientSecret: "",
			Scopes: []string{"openid"}, JITEnabled: true, DefaultRole: "analyst",
		}))
		assert.False(t, id.OIDCEnabled(t.Context()), "a secretless config is not usable")

		// A secret but no external URL: the redirect can't be derived, so the resolver treats it as not configured; OIDCEnabled agrees.
		require.NoError(t, bootstrap.SeedOIDCConfig(t.Context(), db, secretKey, bootstrap.OIDCSeedInput{
			Issuer: "https://idp.example.com", ClientID: "cid", ClientSecret: "real",
			Scopes: []string{"openid"}, JITEnabled: true, DefaultRole: "analyst", Force: true,
		}))
		assert.False(t, id.OIDCEnabled(t.Context()), "no external URL means no derivable redirect, so not usable")

		// Secret + external URL: fully usable.
		require.NoError(t, bootstrap.SeedOIDCConfig(t.Context(), db, secretKey, bootstrap.OIDCSeedInput{
			Issuer: "https://idp.example.com", ClientID: "cid", ClientSecret: "real",
			Scopes: []string{"openid"}, JITEnabled: true, DefaultRole: "analyst", ExternalURL: "https://edr.example.com", Force: true,
		}))
		assert.True(t, id.OIDCEnabled(t.Context()), "a config with a secret and external URL is usable")
	})
}
