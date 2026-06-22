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

// fakeStore is an in-memory configStore (read side). cfg nil => ErrNotFound; err overrides with an arbitrary failure.
type fakeStore struct {
	cfg *ssoconfig.Config
	err error
}

func (f *fakeStore) Get(context.Context) (*ssoconfig.Config, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.cfg == nil {
		return nil, ssoconfig.ErrNotFound
	}
	return f.cfg, nil
}

// fakeAppCfg is an in-memory appConfigStore (read side). err overrides with an arbitrary failure.
type fakeAppCfg struct {
	cfg     appconfig.AppConfig
	version int64
	err     error
}

func (f *fakeAppCfg) Get(context.Context) (appconfig.AppConfig, int64, error) {
	if f.err != nil {
		return appconfig.AppConfig{}, 0, f.err
	}
	return f.cfg, f.version, nil
}

// captureApply records the transactional write the handler requests, and can inject an error (e.g. a version conflict). It stands in
// for the bootstrap-provided transaction so the handler is testable without a DB.
type captureApply struct {
	called          bool
	oidcIn          ssoconfig.UpsertInput
	appCfg          appconfig.AppConfig
	expectedVersion int64
	updatedBy       int64
	err             error
}

func (c *captureApply) fn(_ context.Context, oidcIn ssoconfig.UpsertInput, appCfg appconfig.AppConfig, expectedVersion int64, updatedBy int64) error {
	c.called = true
	c.oidcIn = oidcIn
	c.appCfg = appCfg
	c.expectedVersion = expectedVersion
	c.updatedBy = updatedBy
	return c.err
}

func noopApply(context.Context, ssoconfig.UpsertInput, appconfig.AppConfig, int64, int64) error {
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
	return r.WithContext(api.WithActor(r.Context(), &api.Actor{UserID: userID, AuthMethod: "oidc"}))
}

func putReq(t *testing.T, body any) *http.Request {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/settings/sso", strings.NewReader(string(b)))
	return withActor(r, 42)
}

func TestHandleGet_unconfiguredReturnsConfiguredFalse(t *testing.T) {
	t.Parallel()
	h := NewHandler(&fakeStore{}, &fakeAppCfg{}, noopApply, allowAuthZ{}, &captureAudit{}, okProbe, nil)
	w := httptest.NewRecorder()
	h.handleGet(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/settings/sso", nil))

	require.Equal(t, http.StatusOK, w.Code)
	var resp configResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Configured)
	assert.False(t, resp.SecretSet)
}

// spec:sso-configuration/the-client-secret-is-encrypted-at-rest-and-write-only-over-the-api/read-never-returns-the-secret
func TestHandleGet_neverReturnsSecret(t *testing.T) {
	t.Parallel()
	store := &fakeStore{cfg: &ssoconfig.Config{
		Issuer: "https://idp.example.com", ClientID: "cid", HasSecret: true,
		Scopes: []string{"openid"}, JITEnabled: true, DefaultRole: "analyst",
	}}
	appCfg := &fakeAppCfg{cfg: appconfig.AppConfig{ExternalURL: "https://edr.example.com"}, version: 1}
	h := NewHandler(store, appCfg, noopApply, allowAuthZ{}, &captureAudit{}, okProbe, nil)
	w := httptest.NewRecorder()
	h.handleGet(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/settings/sso", nil))

	require.Equal(t, http.StatusOK, w.Code)
	assert.NotContains(t, strings.ToLower(w.Body.String()), "secret\":\"", "response must not carry a secret value")
	var resp configResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Configured)
	assert.True(t, resp.SecretSet)
	assert.Equal(t, "https://edr.example.com", resp.ExternalURL)
	assert.Equal(t, "https://edr.example.com/api/auth/callback", resp.RedirectURL, "redirect is derived read-only from external URL")
}

func TestHandleGet_deniedIsForbidden(t *testing.T) {
	t.Parallel()
	h := NewHandler(&fakeStore{}, &fakeAppCfg{}, noopApply, denyAuthZ{}, &captureAudit{}, okProbe, nil)
	w := httptest.NewRecorder()
	h.handleGet(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/settings/sso", nil))
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// spec:sso-configuration/every-configuration-mutation-is-audited/saving-a-change-writes-an-audit-row
func TestHandleUpdate_validRotatesSecretAtomicallyAndAudits(t *testing.T) {
	t.Parallel()
	ap := &captureApply{}
	audit := &captureAudit{}
	// Pre-populate the read store so the handler's post-write response re-read succeeds (the fake apply records but does not persist).
	store := &fakeStore{cfg: &ssoconfig.Config{Issuer: "https://idp.example.com", ClientID: "cid", HasSecret: true}}
	h := NewHandler(store, &fakeAppCfg{version: 3}, ap.fn, allowAuthZ{}, audit, okProbe, nil)

	secret := "rotate-me"
	w := httptest.NewRecorder()
	h.handleUpdate(w, putReq(t, updateRequest{
		Issuer: "https://idp.example.com", ClientID: "cid", ClientSecret: &secret,
		ExternalURL: "https://edr.example.com", Scopes: []string{"openid", "email"}, JITEnabled: true, DefaultRole: "analyst",
	}))

	require.Equal(t, http.StatusOK, w.Code)
	require.True(t, ap.called, "the transactional apply must be invoked")
	require.NotNil(t, ap.oidcIn.NewSecret)
	assert.Equal(t, "rotate-me", *ap.oidcIn.NewSecret)
	assert.Equal(t, int64(42), ap.updatedBy)
	assert.Equal(t, "https://edr.example.com", ap.appCfg.ExternalURL)
	assert.Equal(t, int64(3), ap.expectedVersion, "the read app-config version must flow into the OCC check")

	require.Len(t, audit.events, 1)
	assert.Equal(t, api.AuditAction("sso.config.updated"), audit.events[0].Action)
	assert.Equal(t, true, audit.events[0].Payload["secret_rotated"])
	for k, v := range audit.events[0].Payload {
		if s, ok := v.(string); ok {
			assert.NotEqual(t, "rotate-me", s, "audit payload key %q leaked the secret", k)
		}
	}
}

// spec:sso-configuration/the-client-secret-is-encrypted-at-rest-and-write-only-over-the-api/update-rotates-the-secret-only-when-provided
func TestHandleUpdate_secretKeepSemantics(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		secret *string
	}{
		{"omitted", nil},
		{"empty string", new("")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ap := &captureApply{}
			store := &fakeStore{cfg: &ssoconfig.Config{Issuer: "https://idp.example.com", ClientID: "cid"}}
			h := NewHandler(store, &fakeAppCfg{}, ap.fn, allowAuthZ{}, &captureAudit{}, okProbe, nil)
			w := httptest.NewRecorder()
			h.handleUpdate(w, putReq(t, updateRequest{
				Issuer: "https://idp.example.com", ClientID: "cid", ClientSecret: tc.secret,
				ExternalURL: "https://edr.example.com", Scopes: []string{"openid"}, JITEnabled: false, DefaultRole: "auditor",
			}))
			require.Equal(t, http.StatusOK, w.Code)
			require.True(t, ap.called)
			assert.Nil(t, ap.oidcIn.NewSecret, "a kept secret must not rotate the stored value")
		})
	}
}

func TestHandleUpdate_versionConflictIs409(t *testing.T) {
	t.Parallel()
	ap := &captureApply{err: appconfig.ErrVersionConflict}
	h := NewHandler(&fakeStore{}, &fakeAppCfg{version: 5}, ap.fn, allowAuthZ{}, &captureAudit{}, okProbe, nil)
	w := httptest.NewRecorder()
	h.handleUpdate(w, putReq(t, updateRequest{
		Issuer: "https://idp.example.com", ClientID: "cid",
		ExternalURL: "https://edr.example.com", Scopes: []string{"openid"}, JITEnabled: true, DefaultRole: "analyst",
	}))
	require.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "version_conflict")
}

// spec:sso-configuration/admin-api-reads-and-updates-the-oidc-configuration-behind-the-chokepoint/invalid-configuration-is-rejected
func TestHandleUpdate_validationRejectsBeforeApply(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		req    updateRequest
		reason string
	}{
		{"bad issuer", updateRequest{Issuer: "not a url", ClientID: "c", ExternalURL: "https://e", Scopes: []string{"openid"}, DefaultRole: "analyst"}, "invalid_issuer"},
		{"missing client id", updateRequest{Issuer: "https://i", ClientID: "", ExternalURL: "https://e", Scopes: []string{"openid"}, DefaultRole: "analyst"}, "missing_client_id"},
		{"bad external url", updateRequest{Issuer: "https://i", ClientID: "c", ExternalURL: "nope", Scopes: []string{"openid"}, DefaultRole: "analyst"}, "invalid_external_url"},
		{"external url with query", updateRequest{Issuer: "https://i", ClientID: "c", ExternalURL: "https://e?x=1", Scopes: []string{"openid"}, DefaultRole: "analyst"}, "invalid_external_url"},
		{"external url with fragment", updateRequest{Issuer: "https://i", ClientID: "c", ExternalURL: "https://e#frag", Scopes: []string{"openid"}, DefaultRole: "analyst"}, "invalid_external_url"},
		{"external url with bare trailing query marker", updateRequest{Issuer: "https://i", ClientID: "c", ExternalURL: "https://e?", Scopes: []string{"openid"}, DefaultRole: "analyst"}, "invalid_external_url"},
		{"issuer with query", updateRequest{Issuer: "https://i?probe=1", ClientID: "c", ExternalURL: "https://e", Scopes: []string{"openid"}, DefaultRole: "analyst"}, "invalid_issuer"},
		{"missing openid", updateRequest{Issuer: "https://i", ClientID: "c", ExternalURL: "https://e", Scopes: []string{"email"}, DefaultRole: "analyst"}, "missing_openid_scope"},
		{"admin default role", updateRequest{Issuer: "https://i", ClientID: "c", ExternalURL: "https://e", Scopes: []string{"openid"}, JITEnabled: true, DefaultRole: "admin"}, "invalid_default_role"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ap := &captureApply{}
			h := NewHandler(&fakeStore{}, &fakeAppCfg{}, ap.fn, allowAuthZ{}, &captureAudit{}, okProbe, nil)
			w := httptest.NewRecorder()
			h.handleUpdate(w, putReq(t, tc.req))
			require.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), tc.reason)
			assert.False(t, ap.called, "an invalid request must not reach the write")
		})
	}
}

func TestHandleTestConnection(t *testing.T) {
	t.Parallel()
	// spec:sso-configuration/test-connection-probes-the-provider-without-persisting/reachable-provider-verifies
	t.Run("reachable", func(t *testing.T) {
		t.Parallel()
		h := NewHandler(&fakeStore{}, &fakeAppCfg{}, noopApply, allowAuthZ{}, &captureAudit{}, okProbe, nil)
		w := httptest.NewRecorder()
		h.handleTestConnection(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", strings.NewReader(`{"issuer":"https://idp.example.com"}`)))
		require.Equal(t, http.StatusOK, w.Code)
		var resp testConnectionResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)
	})

	t.Run("invalid candidate issuer is 400", func(t *testing.T) {
		t.Parallel()
		probed := false
		h := NewHandler(&fakeStore{}, &fakeAppCfg{}, noopApply, allowAuthZ{}, &captureAudit{},
			func(context.Context, string) error { probed = true; return nil }, nil)
		w := httptest.NewRecorder()
		h.handleTestConnection(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", strings.NewReader(`{"issuer":"not a url"}`)))
		require.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "invalid_issuer")
		assert.False(t, probed, "a malformed issuer must not trigger a network probe")
	})

	// spec:sso-configuration/test-connection-probes-the-provider-without-persisting/unreachable-provider-fails-with-a-reason
	t.Run("unreachable returns ok=false with reason", func(t *testing.T) {
		t.Parallel()
		failProbe := func(context.Context, string) error { return errors.New("discovery unreachable") }
		h := NewHandler(&fakeStore{}, &fakeAppCfg{}, noopApply, allowAuthZ{}, &captureAudit{}, failProbe, nil)
		w := httptest.NewRecorder()
		h.handleTestConnection(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", strings.NewReader(`{"issuer":"https://down.example.com"}`)))
		require.Equal(t, http.StatusOK, w.Code)
		var resp testConnectionResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.OK)
		assert.Contains(t, resp.Reason, "unreachable")
	})
}

// --- error / edge branch coverage -------------------------------------------------

func errStore() *fakeStore   { return &fakeStore{err: errors.New("boom")} }
func errAppCfg() *fakeAppCfg { return &fakeAppCfg{err: errors.New("boom")} }
func okStoreCfg() *fakeStore {
	return &fakeStore{cfg: &ssoconfig.Config{Issuer: "https://idp", ClientID: "cid"}}
}
func validUpdateBody() updateRequest {
	return updateRequest{Issuer: "https://idp.example.com", ClientID: "cid", ExternalURL: "https://edr.example.com", Scopes: []string{"openid"}, JITEnabled: true, DefaultRole: "analyst"}
}

func TestHandleGet_storeErrorsAre500(t *testing.T) {
	t.Parallel()
	t.Run("app config read error", func(t *testing.T) {
		t.Parallel()
		h := NewHandler(&fakeStore{}, errAppCfg(), noopApply, allowAuthZ{}, &captureAudit{}, okProbe, nil)
		w := httptest.NewRecorder()
		h.handleGet(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil))
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
	t.Run("oidc config read error", func(t *testing.T) {
		t.Parallel()
		h := NewHandler(errStore(), &fakeAppCfg{}, noopApply, allowAuthZ{}, &captureAudit{}, okProbe, nil)
		w := httptest.NewRecorder()
		h.handleGet(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil))
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestHandleUpdate_errorBranches(t *testing.T) {
	t.Parallel()
	t.Run("no actor on context is 500", func(t *testing.T) {
		t.Parallel()
		h := NewHandler(okStoreCfg(), &fakeAppCfg{}, noopApply, allowAuthZ{}, &captureAudit{}, okProbe, nil)
		// Marshal through `any` so gosec G117 doesn't flag the concrete client_secret field (the fixture carries no real secret).
		var body any = validUpdateBody()
		b, _ := json.Marshal(body)
		// No withActor wrapper, so ActorFromContext fails.
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/x", strings.NewReader(string(b)))
		w := httptest.NewRecorder()
		h.handleUpdate(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
	t.Run("app config read error is 500", func(t *testing.T) {
		t.Parallel()
		h := NewHandler(okStoreCfg(), errAppCfg(), noopApply, allowAuthZ{}, &captureAudit{}, okProbe, nil)
		w := httptest.NewRecorder()
		h.handleUpdate(w, putReq(t, validUpdateBody()))
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
	t.Run("apply generic error is 500", func(t *testing.T) {
		t.Parallel()
		ap := &captureApply{err: errors.New("tx failed")}
		h := NewHandler(okStoreCfg(), &fakeAppCfg{}, ap.fn, allowAuthZ{}, &captureAudit{}, okProbe, nil)
		w := httptest.NewRecorder()
		h.handleUpdate(w, putReq(t, validUpdateBody()))
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
	t.Run("invalid json is 400", func(t *testing.T) {
		t.Parallel()
		h := NewHandler(okStoreCfg(), &fakeAppCfg{}, noopApply, allowAuthZ{}, &captureAudit{}, okProbe, nil)
		req := withActor(httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/x", strings.NewReader("{not json")), 42)
		w := httptest.NewRecorder()
		h.handleUpdate(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "invalid_json")
	})
	t.Run("oversized body is 413", func(t *testing.T) {
		t.Parallel()
		h := NewHandler(okStoreCfg(), &fakeAppCfg{}, noopApply, allowAuthZ{}, &captureAudit{}, okProbe, nil)
		big := strings.Repeat("a", (1<<16)+10)
		req := withActor(httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/x", strings.NewReader(big)), 42)
		w := httptest.NewRecorder()
		h.handleUpdate(w, req)
		assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	})
	t.Run("nil audit recorder does not panic", func(t *testing.T) {
		t.Parallel()
		h := NewHandler(okStoreCfg(), &fakeAppCfg{}, noopApply, allowAuthZ{}, nil, okProbe, nil)
		w := httptest.NewRecorder()
		h.handleUpdate(w, putReq(t, validUpdateBody()))
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestHandleTestConnection_storedIssuerAndErrors(t *testing.T) {
	t.Parallel()
	t.Run("empty issuer unconfigured is 400 no_issuer", func(t *testing.T) {
		t.Parallel()
		h := NewHandler(&fakeStore{}, &fakeAppCfg{}, noopApply, allowAuthZ{}, &captureAudit{}, okProbe, nil)
		w := httptest.NewRecorder()
		h.handleTestConnection(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", strings.NewReader(`{}`)))
		require.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "no_issuer")
	})
	t.Run("empty issuer falls back to stored", func(t *testing.T) {
		t.Parallel()
		probed := ""
		h := NewHandler(okStoreCfg(), &fakeAppCfg{}, noopApply, allowAuthZ{}, &captureAudit{},
			func(_ context.Context, issuer string) error { probed = issuer; return nil }, nil)
		w := httptest.NewRecorder()
		h.handleTestConnection(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", strings.NewReader(`{}`)))
		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "https://idp", probed, "falls back to the stored issuer")
	})
	t.Run("stored read error is 500", func(t *testing.T) {
		t.Parallel()
		h := NewHandler(errStore(), &fakeAppCfg{}, noopApply, allowAuthZ{}, &captureAudit{}, okProbe, nil)
		w := httptest.NewRecorder()
		h.handleTestConnection(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", strings.NewReader(`{}`)))
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}
