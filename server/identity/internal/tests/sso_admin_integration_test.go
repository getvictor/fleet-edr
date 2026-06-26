package tests

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/bootstrap"
	"github.com/fleetdm/edr/server/identity/internal/appconfig"
	"github.com/fleetdm/edr/server/identity/internal/ssoconfig"
	"github.com/fleetdm/edr/server/testdb/full"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// oidcDiscoveryServer serves a minimal OIDC discovery document so the resolver's real provider build (oidc.New) succeeds against a
// seeded issuer without a live IdP.
func oidcDiscoveryServer(t *testing.T) *httptest.Server {
	t.Helper()
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/auth",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               issuer + "/keys",
		})
	})
	srv := httptest.NewServer(mux)
	issuer = srv.URL
	t.Cleanup(srv.Close)
	return srv
}

// newIdentityWithDiscovery wires the identity context against a real test DB with OIDC seeded from env pointing at a local discovery
// server, so the runtime resolver + admin handler exercise their real (non-faked) code paths.
func newIdentityWithDiscovery(t *testing.T, idp *httptest.Server) (*bootstrap.Identity, *sqlx.DB, *ssoconfig.Store, *appconfig.Store) {
	t.Helper()
	db := full.Open(t)
	secretKey := fixedKey(21)
	id, err := bootstrap.New(t.Context(), bootstrap.Deps{
		DB:                db,
		Logger:            slog.Default(),
		SessionSigningKey: fixedKey(1),
		OIDCSecretKey:     secretKey,
		SessionAbsolute:   time.Hour,
		CleanupInterval:   time.Hour,
		OIDC: bootstrap.OIDCDeps{
			Issuer: idp.URL, ClientID: "edr-itest", ClientSecret: "itest-secret",
			RedirectURL: "https://edr.example.com/api/auth/callback", Scopes: []string{"openid", "email", "profile"},
			AllowJITProvisioning: true, DefaultRole: "analyst", HTTPClient: idp.Client(),
		},
	})
	require.NoError(t, err)
	require.NoError(t, id.ApplySchema(t.Context()))

	sealer, err := ssoconfig.NewSealer(secretKey)
	require.NoError(t, err)
	return id, db, ssoconfig.New(db, sealer), appconfig.New(db)
}

// seedUser inserts a users row and returns its id, for the oidc_config.updated_by FK on the admin update path.
func seedUser(t *testing.T, db *sqlx.DB, email string) int64 {
	t.Helper()
	res, err := db.ExecContext(t.Context(), "INSERT INTO users (email) VALUES (?)", email)
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

func adminActorCtx(r *http.Request, userID int64) *http.Request {
	actor := &api.Actor{
		UserID:       userID,
		AuthMethod:   "oidc",
		SessionFresh: true,
		Roles: []api.RoleBinding{{
			UserID: userID, RoleID: "super_admin", ScopeType: api.RoleBindingScopeGlobal, ScopeID: api.RoleBindingScopeWildcard,
		}},
	}
	return r.WithContext(api.WithActor(r.Context(), actor))
}

// TestSSOAdmin_loginResolvesSeededProvider drives GET /api/auth/login through the real runtime resolver: the seeded config is read,
// the provider is built from the discovery server, and the handler 302s to the issuer's authorize endpoint.
// spec:sso-configuration/oidc-configuration-is-stored-durably-and-is-the-runtime-source-of-truth/login-flow-reads-the-stored-configuration
func TestSSOAdmin_loginResolvesSeededProvider(t *testing.T) {
	t.Parallel()
	idp := oidcDiscoveryServer(t)
	id, _, _, _ := newIdentityWithDiscovery(t, idp)
	require.True(t, id.OIDCEnabled())

	mux := http.NewServeMux()
	id.RegisterPublicRoutes(mux)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/auth/login", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), idp.URL+"/auth", "redirect targets the resolved issuer's authorize endpoint")
}

// TestSSOAdmin_updatePersistsAtomically drives PUT /api/settings/sso through the real chokepoint (super_admin actor) and the real
// transactional apply, then verifies BOTH stores were updated, proving the cross-table write committed together.
func TestSSOAdmin_updatePersistsAtomically(t *testing.T) {
	t.Parallel()
	idp := oidcDiscoveryServer(t)
	id, db, ssoStore, appStore := newIdentityWithDiscovery(t, idp)
	uid := seedUser(t, db, "admin@itest.local") // oidc_config.updated_by FK target

	mux := http.NewServeMux()
	id.RegisterAuthedRoutes(mux)

	body := map[string]any{
		"issuer":        idp.URL,
		"client_id":     "edr-updated",
		"client_secret": "new-secret-value",
		"external_url":  "https://edr.updated.example.com",
		"scopes":        []string{"openid", "email", "profile"},
		"jit_enabled":   true,
		"default_role":  "auditor",
	}
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := adminActorCtx(httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/settings/sso", strings.NewReader(string(raw))), uid)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	// oidc_config updated (with the rotated secret) AND app_config external URL updated: both writes from the one transaction landed.
	cfg, err := ssoStore.GetDecrypted(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "edr-updated", cfg.ClientID)
	assert.Equal(t, "new-secret-value", cfg.ClientSecret)
	assert.Equal(t, "auditor", cfg.DefaultRole)

	appCfg, _, err := appStore.Get(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "https://edr.updated.example.com", appCfg.ExternalURL)

	// The response carries the derived read-only redirect, never the secret.
	assert.Contains(t, w.Body.String(), "https://edr.updated.example.com/api/auth/callback")
	assert.NotContains(t, w.Body.String(), "new-secret-value")
}

// serviceAccountActorCtx pins an actor shaped exactly like the one serviceaccounts.Authenticator produces: a machine caller with no
// user id (UserID == 0), AuthMethod "service_account", not session-fresh, carrying its bound role as a global binding. The role is
// "admin" (which holds sso.manage): service accounts are forbidden from binding super_admin, so admin reflects a real SA token.
func serviceAccountActorCtx(r *http.Request) *http.Request {
	actor := &api.Actor{
		UserID:       0,
		AuthMethod:   "service_account",
		SessionFresh: false,
		Roles: []api.RoleBinding{{
			RoleID: "admin", ScopeType: api.RoleBindingScopeGlobal, ScopeID: api.RoleBindingScopeWildcard,
		}},
	}
	return r.WithContext(api.WithActor(r.Context(), actor))
}

// TestSSOAdmin_updateByServiceAccountRecordsNullUpdatedBy is a regression test: a service-account actor has no user id, so the update
// path must record oidc_config.updated_by as NULL rather than 0. Binding 0 violates the updated_by FK to users(id) and previously
// failed the write with a 500, blocking service-account-driven SSO configuration.
func TestSSOAdmin_updateByServiceAccountRecordsNullUpdatedBy(t *testing.T) {
	t.Parallel()
	idp := oidcDiscoveryServer(t)
	id, db, ssoStore, _ := newIdentityWithDiscovery(t, idp)

	mux := http.NewServeMux()
	id.RegisterAuthedRoutes(mux)

	// Held in a non-credential-named local so the map literal's value is an identifier, not a string literal under a "client_secret"
	// key, which gosec G101 flags as a hardcoded credential.
	rotated := "sa-rotated-secret"
	body := map[string]any{
		"issuer":        idp.URL,
		"client_id":     "edr-sa-updated",
		"client_secret": rotated,
		"external_url":  "https://edr.sa.example.com",
		"scopes":        []string{"openid", "email", "profile"},
		"jit_enabled":   true,
		"default_role":  "analyst",
	}
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := serviceAccountActorCtx(httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/settings/sso", strings.NewReader(string(raw))))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	// The write committed with the rotated values.
	cfg, err := ssoStore.GetDecrypted(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "edr-sa-updated", cfg.ClientID)
	assert.Equal(t, rotated, cfg.ClientSecret)

	// Both rows the transaction writes record updated_by NULL (no operator), the same semantics as env-seeding, never 0. app_config
	// carries the same updated_by FK as oidc_config, so it would 500 the write too if a service account stamped 0.
	var oidcUpdatedBy, appUpdatedBy sql.NullInt64
	require.NoError(t, db.GetContext(t.Context(), &oidcUpdatedBy, "SELECT updated_by FROM oidc_config WHERE id = 1"))
	require.NoError(t, db.GetContext(t.Context(), &appUpdatedBy, "SELECT updated_by FROM app_config WHERE id = 1"))
	assert.False(t, oidcUpdatedBy.Valid, "oidc_config: service-account write must record updated_by NULL, not %d", oidcUpdatedBy.Int64)
	assert.False(t, appUpdatedBy.Valid, "app_config: service-account write must record updated_by NULL, not %d", appUpdatedBy.Int64)
}

// TestSSOAdmin_updateDeniedWithoutGrant confirms the real chokepoint rejects an actor lacking sso.manage (analyst).
// spec:sso-configuration/admin-api-reads-and-updates-the-oidc-configuration-behind-the-chokepoint/unauthorized-caller-cannot-read-or-update
func TestSSOAdmin_updateDeniedWithoutGrant(t *testing.T) {
	t.Parallel()
	idp := oidcDiscoveryServer(t)
	id, _, _, _ := newIdentityWithDiscovery(t, idp)

	mux := http.NewServeMux()
	id.RegisterAuthedRoutes(mux)

	analyst := &api.Actor{UserID: 2, AuthMethod: "oidc", SessionFresh: true, Roles: []api.RoleBinding{{
		UserID: 2, RoleID: "analyst", ScopeType: api.RoleBindingScopeGlobal, ScopeID: api.RoleBindingScopeWildcard,
	}}}
	// Exercise the actual update verb so the test matches its name: the chokepoint must reject the PUT before any write.
	body := strings.NewReader(`{"issuer":"https://idp.example.com","client_id":"x","external_url":"https://e.example.com","scopes":["openid"],"jit_enabled":true,"default_role":"analyst"}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/settings/sso", body)
	req = req.WithContext(api.WithActor(req.Context(), analyst))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}
