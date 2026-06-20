package ssoadmin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/appconfig"
	"github.com/fleetdm/edr/server/identity/internal/ssoconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeStore is an in-memory configStore. cfg nil => ErrNotFound.
type fakeStore struct {
	cfg  *ssoconfig.Config
	last *ssoconfig.UpsertInput
}

func (f *fakeStore) Get(context.Context) (*ssoconfig.Config, error) {
	if f.cfg == nil {
		return nil, ssoconfig.ErrNotFound
	}
	return f.cfg, nil
}

func (f *fakeStore) Upsert(_ context.Context, in ssoconfig.UpsertInput) error {
	f.last = &in
	// Reflect the write into cfg so the handler's re-read returns the new values (secret tracked separately as HasSecret).
	f.cfg = &ssoconfig.Config{
		Issuer: in.Issuer, ClientID: in.ClientID, Scopes: in.Scopes,
		JITEnabled: in.JITEnabled, DefaultRole: in.DefaultRole,
		HasSecret: in.NewSecret != nil || (f.cfg != nil && f.cfg.HasSecret),
	}
	return nil
}

// fakeAppCfg is an in-memory appConfigStore.
type fakeAppCfg struct {
	cfg  appconfig.AppConfig
	last *appconfig.AppConfig
}

func (f *fakeAppCfg) Get(context.Context) (appconfig.AppConfig, int64, error) {
	return f.cfg, 1, nil
}

func (f *fakeAppCfg) Put(_ context.Context, cfg appconfig.AppConfig, _ *int64) error {
	f.cfg = cfg
	f.last = &cfg
	return nil
}

type allowAuthZ struct{}

func (allowAuthZ) Allow(context.Context, api.Action, api.Resource) (api.Decision, error) {
	return api.Decision{Allow: true, Reason: "granted"}, nil
}

type denyAuthZ struct{}

func (denyAuthZ) Allow(context.Context, api.Action, api.Resource) (api.Decision, error) {
	return api.Decision{Allow: false, Reason: "no_matching_rule"}, nil
}

type captureAudit struct{ events []api.AuditEvent }

func (c *captureAudit) Record(_ context.Context, e api.AuditEvent) error {
	c.events = append(c.events, e)
	return nil
}

func okProbe(context.Context, string) error { return nil }

// withActor pins an actor on the request context so handleUpdate's ActorFromContext succeeds.
func withActor(r *http.Request, userID int64) *http.Request {
	ctx := api.WithActor(r.Context(), &api.Actor{UserID: userID, AuthMethod: "oidc"})
	return r.WithContext(ctx)
}

func TestHandleGet_unconfiguredReturnsConfiguredFalse(t *testing.T) {
	t.Parallel()
	h := NewHandler(&fakeStore{}, &fakeAppCfg{}, allowAuthZ{}, &captureAudit{}, okProbe, nil)
	w := httptest.NewRecorder()
	h.handleGet(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/settings/sso", nil))

	require.Equal(t, http.StatusOK, w.Code)
	var resp configResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Configured)
	assert.False(t, resp.SecretSet)
}

func TestHandleGet_neverReturnsSecret(t *testing.T) {
	t.Parallel()
	store := &fakeStore{cfg: &ssoconfig.Config{
		Issuer: "https://idp.example.com", ClientID: "cid", HasSecret: true,
		Scopes: []string{"openid"}, JITEnabled: true, DefaultRole: "analyst",
	}}
	h := NewHandler(store, &fakeAppCfg{}, allowAuthZ{}, &captureAudit{}, okProbe, nil)
	w := httptest.NewRecorder()
	h.handleGet(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/settings/sso", nil))

	require.Equal(t, http.StatusOK, w.Code)
	assert.NotContains(t, strings.ToLower(w.Body.String()), "secret\":\"", "response must not carry a secret value")
	var resp configResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Configured)
	assert.True(t, resp.SecretSet)
}

func TestHandleGet_deniedIsForbidden(t *testing.T) {
	t.Parallel()
	h := NewHandler(&fakeStore{}, &fakeAppCfg{}, denyAuthZ{}, &captureAudit{}, okProbe, nil)
	w := httptest.NewRecorder()
	h.handleGet(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/settings/sso", nil))
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func putReq(t *testing.T, body any) *http.Request {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/settings/sso", strings.NewReader(string(b)))
	return withActor(r, 42)
}

func TestHandleUpdate_validRotatesSecretAndAudits(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	audit := &captureAudit{}
	h := NewHandler(store, &fakeAppCfg{}, allowAuthZ{}, audit, okProbe, nil)

	secret := "rotate-me"
	w := httptest.NewRecorder()
	h.handleUpdate(w, putReq(t, updateRequest{
		Issuer: "https://idp.example.com", ClientID: "cid", ClientSecret: &secret,
		ExternalURL: "https://edr/cb", Scopes: []string{"openid", "email"}, JITEnabled: true, DefaultRole: "analyst",
	}))

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, store.last)
	require.NotNil(t, store.last.NewSecret)
	assert.Equal(t, "rotate-me", *store.last.NewSecret)
	require.NotNil(t, store.last.UpdatedBy)
	assert.Equal(t, int64(42), *store.last.UpdatedBy)

	require.Len(t, audit.events, 1)
	assert.Equal(t, api.AuditAction("sso.config.updated"), audit.events[0].Action)
	assert.Equal(t, true, audit.events[0].Payload["secret_rotated"])
	// The audit payload must not carry the secret value.
	for k, v := range audit.events[0].Payload {
		if s, ok := v.(string); ok {
			assert.NotEqual(t, "rotate-me", s, "audit payload key %q leaked the secret", k)
		}
	}
}

func TestHandleUpdate_omittedSecretIsKept(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	h := NewHandler(store, &fakeAppCfg{}, allowAuthZ{}, &captureAudit{}, okProbe, nil)

	w := httptest.NewRecorder()
	h.handleUpdate(w, putReq(t, updateRequest{
		Issuer: "https://idp.example.com", ClientID: "cid", ClientSecret: nil,
		ExternalURL: "https://edr/cb", Scopes: []string{"openid"}, JITEnabled: false, DefaultRole: "auditor",
	}))

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, store.last)
	assert.Nil(t, store.last.NewSecret, "omitted client_secret must not rotate the stored secret")
}

func TestHandleUpdate_emptySecretStringIsKept(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	h := NewHandler(store, &fakeAppCfg{}, allowAuthZ{}, &captureAudit{}, okProbe, nil)
	empty := ""
	w := httptest.NewRecorder()
	h.handleUpdate(w, putReq(t, updateRequest{
		Issuer: "https://idp.example.com", ClientID: "cid", ClientSecret: &empty,
		ExternalURL: "https://edr/cb", Scopes: []string{"openid"}, JITEnabled: true, DefaultRole: "analyst",
	}))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Nil(t, store.last.NewSecret, "empty client_secret string must be treated as keep")
}

func TestHandleUpdate_validationRejects(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		req    updateRequest
		reason string
	}{
		{"bad issuer", updateRequest{Issuer: "not a url", ClientID: "c", ExternalURL: "https://e/cb", Scopes: []string{"openid"}, DefaultRole: "analyst"}, "invalid_issuer"},
		{"missing client id", updateRequest{Issuer: "https://i", ClientID: "", ExternalURL: "https://e/cb", Scopes: []string{"openid"}, DefaultRole: "analyst"}, "missing_client_id"},
		{"bad external url", updateRequest{Issuer: "https://i", ClientID: "c", ExternalURL: "nope", Scopes: []string{"openid"}, DefaultRole: "analyst"}, "invalid_external_url"},
		{"missing openid", updateRequest{Issuer: "https://i", ClientID: "c", ExternalURL: "https://e/cb", Scopes: []string{"email"}, DefaultRole: "analyst"}, "missing_openid_scope"},
		{"admin default role", updateRequest{Issuer: "https://i", ClientID: "c", ExternalURL: "https://e/cb", Scopes: []string{"openid"}, JITEnabled: true, DefaultRole: "admin"}, "invalid_default_role"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := &fakeStore{}
			h := NewHandler(store, &fakeAppCfg{}, allowAuthZ{}, &captureAudit{}, okProbe, nil)
			w := httptest.NewRecorder()
			h.handleUpdate(w, putReq(t, tc.req))
			require.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), tc.reason)
			assert.Nil(t, store.last, "invalid request must not persist")
		})
	}
}

func TestHandleTestConnection_passAndFail(t *testing.T) {
	t.Parallel()
	t.Run("reachable", func(t *testing.T) {
		t.Parallel()
		h := NewHandler(&fakeStore{}, &fakeAppCfg{}, allowAuthZ{}, &captureAudit{}, okProbe, nil)
		w := httptest.NewRecorder()
		body := `{"issuer":"https://idp.example.com"}`
		h.handleTestConnection(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/settings/sso/test-connection", strings.NewReader(body)))
		require.Equal(t, http.StatusOK, w.Code)
		var resp testConnectionResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)
	})

	t.Run("unreachable returns ok=false with reason, no persist", func(t *testing.T) {
		t.Parallel()
		store := &fakeStore{}
		failProbe := func(context.Context, string) error { return errors.New("discovery unreachable") }
		h := NewHandler(store, &fakeAppCfg{}, allowAuthZ{}, &captureAudit{}, failProbe, nil)
		w := httptest.NewRecorder()
		body := `{"issuer":"https://down.example.com"}`
		h.handleTestConnection(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/settings/sso/test-connection", strings.NewReader(body)))
		require.Equal(t, http.StatusOK, w.Code)
		var resp testConnectionResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.OK)
		assert.Contains(t, resp.Reason, "unreachable")
		assert.Nil(t, store.last, "test-connection must not persist")
	})
}
