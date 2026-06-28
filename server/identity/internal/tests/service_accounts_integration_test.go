package tests

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/bootstrap"
	"github.com/fleetdm/edr/server/testdb/full"
)

func newServiceAccountIdentity(t *testing.T) (*bootstrap.Identity, *sqlx.DB) {
	t.Helper()
	db := full.Open(t)
	id, err := bootstrap.New(t.Context(), bootstrap.Deps{
		DB:                            db,
		Logger:                        slog.Default(),
		SessionSigningKey:             saFixedKey(1),
		ServiceAccountTokenSigningKey: saFixedKey(2),
		SessionAbsolute:               time.Hour,
		CleanupInterval:               time.Hour,
	})
	require.NoError(t, err)
	require.NoError(t, id.ApplySchema(t.Context()))
	return id, db
}

func saFixedKey(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

// superAdminReq injects a super_admin actor (global wildcard binding) for the given user id, matching how the session middleware would
// pin one. The user id must reference a real users row (the created_by FK on create).
func superAdminReq(r *http.Request, uid int64) *http.Request {
	actor := &api.Actor{
		Principal: api.UserPrincipal(uid, "op@example.com"), AuthMethod: "oidc", SessionFresh: true,
		Roles: []api.RoleBinding{{
			UserID: uid, RoleID: "super_admin", ScopeType: api.RoleBindingScopeGlobal, ScopeID: api.RoleBindingScopeWildcard,
		}},
	}
	return r.WithContext(api.WithActor(r.Context(), actor))
}

// spec:server-identity-service-accounts/the-client-credential-is-hashed-at-rest-and-shown-once/secret-is-returned-once-and-never-again
// spec:server-identity-service-accounts/the-client-credential-is-hashed-at-rest-and-shown-once/secret-is-stored-hashed
// spec:server-identity-service-accounts/the-token-endpoint-issues-short-lived-self-validating-access-tokens/valid-credential-mints-a-short-lived-token
// spec:server-identity-service-accounts/the-token-endpoint-issues-short-lived-self-validating-access-tokens/revoked-credential-is-refused
// spec:server-identity-service-accounts/access-tokens-are-validated-statelessly-on-the-api-request-path/valid-token-authenticates-without-a-database-read
// spec:server-identity-service-accounts/revocation-takes-effect-via-short-ttl-and-a-per-replica-epoch-snapshot/a-revoked-service-account-stops-working-within-the-refresh-window
// spec:server-identity-authentication/the-api-accepts-a-bearer-access-token-as-a-second-transport/bearer-token-authenticates-a-service-account-principal
// spec:server-identity-service-accounts/a-service-account-is-a-non-human-principal-bound-to-a-single-role/service-account-binds-to-one-role
func TestServiceAccounts_endToEnd(t *testing.T) {
	t.Parallel()
	id, db := newServiceAccountIdentity(t)
	uid := seedUser(t, db, "admin@itest.local")

	authed := http.NewServeMux()
	id.RegisterAuthedRoutes(authed)
	public := http.NewServeMux()
	id.RegisterPublicRoutes(public)

	// 1. Create a service account (super_admin). The one-time secret comes back here and never again.
	createBody, _ := json.Marshal(map[string]any{"name": "ci-bot", "role": "analyst"})
	cw := httptest.NewRecorder()
	authed.ServeHTTP(cw, superAdminReq(httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/settings/service-accounts", strings.NewReader(string(createBody))), uid))
	require.Equal(t, http.StatusCreated, cw.Code, "body: %s", cw.Body.String())
	var created struct {
		ID       int64  `json:"id"`
		ClientID string `json:"client_id"`
		Secret   string `json:"secret"`
		Role     string `json:"role"`
	}
	require.NoError(t, json.Unmarshal(cw.Body.Bytes(), &created))
	require.NotEmpty(t, created.Secret)
	require.Equal(t, "analyst", created.Role)

	// The stored row holds only a hash, never the plaintext secret.
	var stored []byte
	require.NoError(t, db.GetContext(t.Context(), &stored, "SELECT secret_hash FROM service_accounts WHERE id = ?", created.ID))
	assert.NotContains(t, string(stored), created.Secret)

	// 2. Exchange the credential for an access token at the public token endpoint.
	accessToken := mintToken(t, public, created.ClientID, created.Secret)

	// 3. The access token authenticates as the bound service-account principal through the API auth middleware.
	probe := id.APIAuthMiddleware()
	require.NotNil(t, probe)
	assertBearerRole(t, probe, accessToken, "analyst", http.StatusOK)

	// 4. A bad secret and an unknown client are both refused at the token endpoint (the latter exercises the store's not-found path).
	bw := httptest.NewRecorder()
	badBody, _ := json.Marshal(map[string]string{"client_id": created.ClientID, "client_secret": "edrsa_wrong"})
	public.ServeHTTP(bw, jsonReq(t, "/api/oauth/token", string(badBody)))
	assert.Equal(t, http.StatusUnauthorized, bw.Code)

	uw := httptest.NewRecorder()
	unknownBody, _ := json.Marshal(map[string]string{"client_id": "sa_does_not_exist", "client_secret": "edrsa_x"})
	public.ServeHTTP(uw, jsonReq(t, "/api/oauth/token", string(unknownBody)))
	assert.Equal(t, http.StatusUnauthorized, uw.Code)

	// 5. Revoke, refresh the per-replica snapshot, and confirm the outstanding token stops validating and no new token can be minted.
	rw := httptest.NewRecorder()
	authed.ServeHTTP(rw, superAdminReq(httptest.NewRequestWithContext(t.Context(), http.MethodDelete,
		"/api/settings/service-accounts/"+strconv.FormatInt(created.ID, 10), nil), uid))
	require.Equal(t, http.StatusOK, rw.Code)
	require.NoError(t, id.ServiceAccountSnapshot().Refresh(t.Context()))

	assertBearerRole(t, probe, accessToken, "", http.StatusUnauthorized) // outstanding token now rejected
	mw := httptest.NewRecorder()
	reBody, _ := json.Marshal(map[string]string{"client_id": created.ClientID, "client_secret": created.Secret})
	public.ServeHTTP(mw, jsonReq(t, "/api/oauth/token", string(reBody)))
	assert.Equal(t, http.StatusUnauthorized, mw.Code, "a revoked credential cannot mint a new token")
}

func TestServiceAccounts_listAndRotate(t *testing.T) {
	t.Parallel()
	id, db := newServiceAccountIdentity(t)
	uid := seedUser(t, db, "admin-lr@itest.local")
	authed := http.NewServeMux()
	id.RegisterAuthedRoutes(authed)
	public := http.NewServeMux()
	id.RegisterPublicRoutes(public)

	// Create.
	createBody, _ := json.Marshal(map[string]any{"name": "rotater", "role": "auditor"})
	cw := httptest.NewRecorder()
	authed.ServeHTTP(cw, superAdminReq(httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/settings/service-accounts", strings.NewReader(string(createBody))), uid))
	require.Equal(t, http.StatusCreated, cw.Code)
	var created struct {
		ID       int64  `json:"id"`
		ClientID string `json:"client_id"`
		Secret   string `json:"secret"`
	}
	require.NoError(t, json.Unmarshal(cw.Body.Bytes(), &created))

	// List shows it as active.
	lw := httptest.NewRecorder()
	authed.ServeHTTP(lw, superAdminReq(httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/settings/service-accounts", nil), uid))
	require.Equal(t, http.StatusOK, lw.Code)
	var list struct {
		ServiceAccounts []struct {
			ClientID string `json:"client_id"`
			Status   string `json:"status"`
		} `json:"service_accounts"`
	}
	require.NoError(t, json.Unmarshal(lw.Body.Bytes(), &list))
	var found bool
	for _, sa := range list.ServiceAccounts {
		if sa.ClientID == created.ClientID {
			found = true
			assert.Equal(t, "active", sa.Status)
		}
	}
	assert.True(t, found, "created account appears in the list")

	// Rotate: a fresh secret, the old one no longer works, the new one does.
	rw := httptest.NewRecorder()
	authed.ServeHTTP(rw, superAdminReq(httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/settings/service-accounts/"+strconv.FormatInt(created.ID, 10)+"/rotate", nil), uid))
	require.Equal(t, http.StatusOK, rw.Code)
	var rotated struct {
		Secret string `json:"secret"`
	}
	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &rotated))
	require.NotEqual(t, created.Secret, rotated.Secret)

	oldw := httptest.NewRecorder()
	oldBody, _ := json.Marshal(map[string]string{"client_id": created.ClientID, "client_secret": created.Secret})
	public.ServeHTTP(oldw, jsonReq(t, "/api/oauth/token", string(oldBody)))
	assert.Equal(t, http.StatusUnauthorized, oldw.Code, "the rotated-away secret no longer mints")

	_ = mintToken(t, public, created.ClientID, rotated.Secret) // the new secret mints
}

// spec:server-identity-service-accounts/a-service-account-is-a-non-human-principal-bound-to-a-single-role/a-service-account-cannot-bind-to-super-admin
func TestServiceAccounts_superAdminRoleRejected(t *testing.T) {
	t.Parallel()
	id, db := newServiceAccountIdentity(t)
	uid := seedUser(t, db, "admin2@itest.local")
	authed := http.NewServeMux()
	id.RegisterAuthedRoutes(authed)

	// admin is permitted (operator discretion); super_admin is never bindable to a non-human credential.
	body, _ := json.Marshal(map[string]any{"name": "x", "role": "super_admin"})
	w := httptest.NewRecorder()
	authed.ServeHTTP(w, superAdminReq(httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/settings/service-accounts", strings.NewReader(string(body))), uid))
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_role")
}

// spec:server-identity-service-accounts/service-accounts-are-managed-from-an-admin-surface-behind-the-chokepoint/unauthorized-caller-cannot-manage-service-accounts
// spec:server-identity-authorization/service-account-management-actions-are-registered-and-admin-scoped/a-role-without-the-grant-is-denied
func TestServiceAccounts_unauthorizedCallerForbidden(t *testing.T) {
	t.Parallel()
	id, _ := newServiceAccountIdentity(t)
	authed := http.NewServeMux()
	id.RegisterAuthedRoutes(authed)

	analyst := &api.Actor{Principal: api.UserPrincipal(2, ""), AuthMethod: "oidc", SessionFresh: true, Roles: []api.RoleBinding{{
		UserID: 2, RoleID: "analyst", ScopeType: api.RoleBindingScopeGlobal, ScopeID: api.RoleBindingScopeWildcard,
	}}}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/settings/service-accounts", nil)
	r = r.WithContext(api.WithActor(r.Context(), analyst))
	w := httptest.NewRecorder()
	authed.ServeHTTP(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func mintToken(t *testing.T, public http.Handler, clientID, secret string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"grant_type": "client_credentials", "client_id": clientID, "client_secret": secret})
	w := httptest.NewRecorder()
	public.ServeHTTP(w, jsonReq(t, "/api/oauth/token", string(body)))
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	var resp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Equal(t, "Bearer", resp.TokenType)
	require.NotEmpty(t, resp.AccessToken)
	return resp.AccessToken
}

// assertBearerRole drives a probe handler behind the API auth middleware with the bearer token and asserts the resulting status and
// (when 200) the actor's resolved role.
func assertBearerRole(t *testing.T, mw func(http.Handler) http.Handler, token, wantRole string, wantStatus int) {
	t.Helper()
	var gotRole string
	probe := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a, ok := api.ActorFromContext(r.Context()); ok && len(a.Roles) > 0 {
			gotRole = a.Roles[0].RoleID
		}
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/hosts", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	probe.ServeHTTP(w, r)
	require.Equal(t, wantStatus, w.Code)
	if wantStatus == http.StatusOK {
		assert.Equal(t, wantRole, gotRole)
	}
}

func jsonReq(t *testing.T, path, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}
