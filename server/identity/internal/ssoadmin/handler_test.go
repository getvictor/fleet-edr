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

// fakeRead is an in-memory ReadFunc source: the snapshot the handler reads, or an arbitrary failure.
type fakeRead struct {
	cfg     *ssoconfig.Config
	appCfg  appconfig.AppConfig
	version Version
	err     error
}

func (f *fakeRead) fn(context.Context) (Snapshot, error) {
	if f.err != nil {
		return Snapshot{}, f.err
	}
	return Snapshot{Config: f.cfg, AppConfig: f.appCfg, Version: f.version}, nil
}

// captureApply records the transactional write the handler requests, and can inject an error (e.g. a version conflict). It stands in
// for the bootstrap-provided transaction so the handler is testable without a DB. saved is what it reports back; the zero value is
// enough for tests that only assert on what was requested.
type captureApply struct {
	called    bool
	oidcIn    ssoconfig.UpsertInput
	appCfg    appconfig.AppConfig
	expected  Expectation
	updatedBy string
	saved     Snapshot
	err       error
}

func (c *captureApply) fn(
	_ context.Context, oidcIn ssoconfig.UpsertInput, appCfg appconfig.AppConfig, expected Expectation, updatedBy string,
) (Snapshot, error) {
	c.called = true
	c.oidcIn = oidcIn
	c.appCfg = appCfg
	c.expected = expected
	c.updatedBy = updatedBy
	if c.err != nil {
		return Snapshot{}, c.err
	}
	return c.saved, nil
}

func noopApply(context.Context, ssoconfig.UpsertInput, appconfig.AppConfig, Expectation, string) (Snapshot, error) {
	return Snapshot{}, nil
}

func noopRead(context.Context) (Snapshot, error) { return Snapshot{}, nil }

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
	return r.WithContext(api.WithActor(r.Context(), &api.Actor{Principal: api.UserPrincipal(userID, ""), AuthMethod: "oidc"}))
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
	h := NewHandler(&fakeStore{}, noopRead, noopApply, allowAuthZ{}, &captureAudit{}, okProbe, nil)
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
	read := &fakeRead{cfg: store.cfg, appCfg: appconfig.AppConfig{ExternalURL: "https://edr.example.com"}, version: Version{OIDC: 2, App: 1}}
	h := NewHandler(store, read.fn, noopApply, allowAuthZ{}, &captureAudit{}, okProbe, nil)
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
	h := NewHandler(&fakeStore{}, noopRead, noopApply, denyAuthZ{}, &captureAudit{}, okProbe, nil)
	w := httptest.NewRecorder()
	h.handleGet(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/settings/sso", nil))
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// spec:sso-configuration/every-configuration-mutation-is-audited/saving-a-change-writes-an-audit-row-naming-the-principal
func TestHandleUpdate_validRotatesSecretAtomicallyAndAudits(t *testing.T) {
	t.Parallel()
	ap := &captureApply{}
	audit := &captureAudit{}
	// Pre-populate the read store so the handler's post-write response re-read succeeds (the fake apply records but does not persist).
	store := &fakeStore{cfg: &ssoconfig.Config{Issuer: "https://idp.example.com", ClientID: "cid", HasSecret: true}}
	h := NewHandler(store, (&fakeRead{version: Version{App: 3}}).fn, ap.fn, allowAuthZ{}, audit, okProbe, nil)

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
	assert.Equal(t, "usr_42", ap.updatedBy, "a human actor stamps updated_by with its principal id")
	assert.Equal(t, "https://edr.example.com", ap.appCfg.ExternalURL)
	assert.Equal(t, int64(3), ap.expected.Version.App, "a caller naming no version is still guarded by the version this request read")
	assert.False(t, ap.expected.Checked, "and the save is an overwrite, because the caller named no version")

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
			h := NewHandler(store, noopRead, ap.fn, allowAuthZ{}, &captureAudit{}, okProbe, nil)
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
	h := NewHandler(&fakeStore{}, (&fakeRead{version: Version{App: 5}}).fn, ap.fn, allowAuthZ{}, &captureAudit{}, okProbe, nil)
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
			h := NewHandler(&fakeStore{}, noopRead, ap.fn, allowAuthZ{}, &captureAudit{}, okProbe, nil)
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
		h := NewHandler(&fakeStore{}, noopRead, noopApply, allowAuthZ{}, &captureAudit{}, okProbe, nil)
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
		h := NewHandler(&fakeStore{}, noopRead, noopApply, allowAuthZ{}, &captureAudit{},
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
		h := NewHandler(&fakeStore{}, noopRead, noopApply, allowAuthZ{}, &captureAudit{}, failProbe, nil)
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

func errStore() *fakeStore { return &fakeStore{err: errors.New("boom")} }
func errRead() ReadFunc    { return (&fakeRead{err: errors.New("boom")}).fn }
func okStoreCfg() *fakeStore {
	return &fakeStore{cfg: &ssoconfig.Config{Issuer: "https://idp", ClientID: "cid"}}
}
func validUpdateBody() updateRequest {
	return updateRequest{Issuer: "https://idp.example.com", ClientID: "cid", ExternalURL: "https://edr.example.com", Scopes: []string{"openid"}, JITEnabled: true, DefaultRole: "analyst"}
}

// Both stored parts now come from one snapshot read, so there is one failure to report rather than the two the handler used to
// distinguish. An erroring config store no longer reaches the GET at all.
func TestHandleGet_storeErrorsAre500(t *testing.T) {
	t.Parallel()
	h := NewHandler(&fakeStore{}, errRead(), noopApply, allowAuthZ{}, &captureAudit{}, okProbe, nil)
	w := httptest.NewRecorder()
	h.handleGet(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestHandleUpdate_errorBranches(t *testing.T) {
	t.Parallel()
	t.Run("no actor on context is 500", func(t *testing.T) {
		t.Parallel()
		h := NewHandler(okStoreCfg(), noopRead, noopApply, allowAuthZ{}, &captureAudit{}, okProbe, nil)
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
		h := NewHandler(okStoreCfg(), errRead(), noopApply, allowAuthZ{}, &captureAudit{}, okProbe, nil)
		w := httptest.NewRecorder()
		h.handleUpdate(w, putReq(t, validUpdateBody()))
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
	t.Run("apply generic error is 500", func(t *testing.T) {
		t.Parallel()
		ap := &captureApply{err: errors.New("tx failed")}
		h := NewHandler(okStoreCfg(), noopRead, ap.fn, allowAuthZ{}, &captureAudit{}, okProbe, nil)
		w := httptest.NewRecorder()
		h.handleUpdate(w, putReq(t, validUpdateBody()))
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
	t.Run("invalid json is 400", func(t *testing.T) {
		t.Parallel()
		h := NewHandler(okStoreCfg(), noopRead, noopApply, allowAuthZ{}, &captureAudit{}, okProbe, nil)
		req := withActor(httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/x", strings.NewReader("{not json")), 42)
		w := httptest.NewRecorder()
		h.handleUpdate(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "invalid_json")
	})
	t.Run("oversized body is 413", func(t *testing.T) {
		t.Parallel()
		h := NewHandler(okStoreCfg(), noopRead, noopApply, allowAuthZ{}, &captureAudit{}, okProbe, nil)
		big := strings.Repeat("a", (1<<16)+10)
		req := withActor(httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/x", strings.NewReader(big)), 42)
		w := httptest.NewRecorder()
		h.handleUpdate(w, req)
		assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	})
	t.Run("nil audit recorder does not panic", func(t *testing.T) {
		t.Parallel()
		h := NewHandler(okStoreCfg(), noopRead, noopApply, allowAuthZ{}, nil, okProbe, nil)
		w := httptest.NewRecorder()
		h.handleUpdate(w, putReq(t, validUpdateBody()))
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestHandleTestConnection_storedIssuerAndErrors(t *testing.T) {
	t.Parallel()
	t.Run("empty issuer unconfigured is 400 no_issuer", func(t *testing.T) {
		t.Parallel()
		h := NewHandler(&fakeStore{}, noopRead, noopApply, allowAuthZ{}, &captureAudit{}, okProbe, nil)
		w := httptest.NewRecorder()
		h.handleTestConnection(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", strings.NewReader(`{}`)))
		require.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "no_issuer")
	})
	t.Run("empty issuer falls back to stored", func(t *testing.T) {
		t.Parallel()
		probed := ""
		h := NewHandler(okStoreCfg(), noopRead, noopApply, allowAuthZ{}, &captureAudit{},
			func(_ context.Context, issuer string) error { probed = issuer; return nil }, nil)
		w := httptest.NewRecorder()
		h.handleTestConnection(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", strings.NewReader(`{}`)))
		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "https://idp", probed, "falls back to the stored issuer")
	})
	t.Run("stored read error is 500", func(t *testing.T) {
		t.Parallel()
		h := NewHandler(errStore(), noopRead, noopApply, allowAuthZ{}, &captureAudit{}, okProbe, nil)
		w := httptest.NewRecorder()
		h.handleTestConnection(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", strings.NewReader(`{}`)))
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// spec:sso-configuration/admin-api-reads-and-updates-the-oidc-configuration-behind-the-chokepoint/a-group-mapped-to-super-admin-is-rejected
func TestHandleUpdate_groupMappingValidation(t *testing.T) {
	t.Parallel()
	base := func(claim string, roles ...ssoconfig.GroupRole) updateRequest {
		return updateRequest{
			Issuer: "https://i", ClientID: "c", ExternalURL: "https://e", Scopes: []string{"openid"}, DefaultRole: "analyst",
			GroupsClaim: claim, GroupRoles: roles,
		}
	}
	long := strings.Repeat("g", maxGroupFieldLen+1)
	cases := []struct {
		name   string
		req    updateRequest
		reason string
	}{
		{"super admin role", base("groups", ssoconfig.GroupRole{Group: "edr-root", Role: "super_admin"}), "invalid_group_role"},
		{"unknown role", base("groups", ssoconfig.GroupRole{Group: "edr-x", Role: "owner"}), "invalid_group_role"},
		{"blank group", base("groups", ssoconfig.GroupRole{Group: "  ", Role: "admin"}), "invalid_group_role"},
		{"overlong group", base("groups", ssoconfig.GroupRole{Group: long, Role: "admin"}), "invalid_group_role"},
		{"group named twice", base("groups",
			ssoconfig.GroupRole{Group: "edr-admins", Role: "admin"},
			ssoconfig.GroupRole{Group: " edr-admins ", Role: "auditor"}), "duplicate_group"},
		{"mappings without a claim", base(" ", ssoconfig.GroupRole{Group: "edr-admins", Role: "admin"}), "missing_groups_claim"},
		{"claim without mappings", base("groups"), "missing_group_roles"},
		{"overlong claim", base(long, ssoconfig.GroupRole{Group: "edr-admins", Role: "admin"}), "invalid_groups_claim"},
		{"overlong non-ASCII group", base("groups", ssoconfig.GroupRole{Group: strings.Repeat("日", maxGroupFieldLen+1), Role: "admin"}),
			"invalid_group_role"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ap := &captureApply{}
			h := NewHandler(&fakeStore{}, noopRead, ap.fn, allowAuthZ{}, &captureAudit{}, okProbe, nil)
			w := httptest.NewRecorder()
			h.handleUpdate(w, putReq(t, tc.req))
			require.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), tc.reason)
			assert.False(t, ap.called, "an invalid request must not reach the write")
		})
	}
}

// spec:sso-configuration/admin-api-reads-and-updates-the-oidc-configuration-behind-the-chokepoint/group-mappings-are-saved-and-read-back
func TestHandleUpdate_groupMappingIsNormalizedWrittenAuditedAndReturned(t *testing.T) {
	t.Parallel()
	ap := &captureApply{}
	audit := &captureAudit{}
	saved := []ssoconfig.GroupRole{{Group: "edr-admins", Role: "admin"}, {Group: "edr-auditors", Role: "auditor"}}
	store := &fakeStore{cfg: &ssoconfig.Config{Issuer: "https://idp.example.com", ClientID: "cid", GroupsClaim: "groups", GroupRoles: saved}}
	// The response is what the write read back inside its own transaction, not a re-read afterwards, so the fake reports it.
	ap.saved = Snapshot{Config: store.cfg, Version: Version{OIDC: 1, App: 1}}
	h := NewHandler(store, noopRead, ap.fn, allowAuthZ{}, audit, okProbe, nil)

	w := httptest.NewRecorder()
	h.handleUpdate(w, putReq(t, updateRequest{
		Issuer: "https://idp.example.com", ClientID: "cid", ExternalURL: "https://edr.example.com", Scopes: []string{"openid"},
		JITEnabled: true, DefaultRole: "analyst",
		GroupsClaim: " groups ",
		GroupRoles:  []ssoconfig.GroupRole{{Group: " edr-admins", Role: "ADMIN"}, {Group: "edr-auditors", Role: "auditor"}},
	}))
	require.Equal(t, http.StatusOK, w.Code)
	require.True(t, ap.called)
	assert.Equal(t, "groups", ap.oidcIn.GroupsClaim)
	assert.Equal(t, saved, ap.oidcIn.GroupRoles, "groups are trimmed and roles lower-cased, in the order submitted")
	require.Len(t, audit.events, 1)
	assert.Equal(t, "groups", audit.events[0].Payload["groups_claim"])
	assert.Equal(t, saved, audit.events[0].Payload["group_roles"])

	var body configResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "groups", body.GroupsClaim)
	assert.Equal(t, saved, body.GroupRoles)
}

// With no mapping stored, the read returns an empty claim and an empty list rather than null, configured or not.
func TestHandleGet_groupRolesIsAnArrayWhenOff(t *testing.T) {
	t.Parallel()
	for name, store := range map[string]*fakeStore{
		"unconfigured": {},
		"configured":   {cfg: &ssoconfig.Config{Issuer: "https://idp.example.com", ClientID: "cid"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := NewHandler(store, noopRead, noopApply, allowAuthZ{}, nil, okProbe, nil)
			w := httptest.NewRecorder()
			h.handleGet(w, withActor(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/settings/sso", nil), 42))
			require.Equal(t, http.StatusOK, w.Code)
			assert.Contains(t, w.Body.String(), `"group_roles":[]`)
			assert.Contains(t, w.Body.String(), `"groups_claim":""`)
		})
	}
}

// The 255 bound is in characters, as the column is: a claim and a group of 255 multi-byte characters are accepted.
func TestHandleUpdate_groupFieldsAreBoundedInCharacters(t *testing.T) {
	t.Parallel()
	wide := strings.Repeat("日", maxGroupFieldLen)
	ap := &captureApply{}
	store := &fakeStore{cfg: &ssoconfig.Config{Issuer: "https://i", ClientID: "c"}}
	h := NewHandler(store, noopRead, ap.fn, allowAuthZ{}, &captureAudit{}, okProbe, nil)
	w := httptest.NewRecorder()
	h.handleUpdate(w, putReq(t, updateRequest{
		Issuer: "https://i", ClientID: "c", ExternalURL: "https://e", Scopes: []string{"openid"}, DefaultRole: "analyst",
		GroupsClaim: wide, GroupRoles: []ssoconfig.GroupRole{{Group: wide, Role: "admin"}},
	}))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, wide, ap.oidcIn.GroupsClaim)
}

// --- optimistic concurrency (issue #1046) ------------------------------------------

// The version a client read is what its save is conditioned on, both parts of it. Passing only one through would leave the other
// open, which is how a save that named a version could still overwrite an external URL somebody changed in the meantime.
func TestHandleUpdate_sendsTheCallersVersionToTheWrite(t *testing.T) {
	t.Parallel()
	ap := &captureApply{}
	// A read that reports something else entirely, so the expectation cannot be coming from here.
	read := &fakeRead{version: Version{OIDC: 99, App: 99}}
	h := NewHandler(okStoreCfg(), read.fn, ap.fn, allowAuthZ{}, &captureAudit{}, okProbe, nil)

	body := validUpdateBody()
	body.Version = new(Version{OIDC: 4, App: 7}.String())
	w := httptest.NewRecorder()
	h.handleUpdate(w, putReq(t, body))

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.True(t, ap.called)
	assert.True(t, ap.expected.Checked, "a caller who named a version gets its save conditioned on it")
	assert.Equal(t, Version{OIDC: 4, App: 7}, ap.expected.Version, "both parts, as the caller read them")
}

// Omitting the version is how a script says "set this configuration, whatever is there". It stays available on purpose: automation
// that means to overwrite should not have to read first. The write is still guarded by the version this request itself read, which
// is what kept a change landing mid-request from being lost before any of this.
func TestHandleUpdate_noVersionIsAnOverwriteGuardedByItsOwnRead(t *testing.T) {
	t.Parallel()
	ap := &captureApply{}
	read := &fakeRead{version: Version{OIDC: 4, App: 7}}
	h := NewHandler(okStoreCfg(), read.fn, ap.fn, allowAuthZ{}, &captureAudit{}, okProbe, nil)

	w := httptest.NewRecorder()
	h.handleUpdate(w, putReq(t, validUpdateBody()))

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.True(t, ap.called)
	assert.False(t, ap.expected.Checked, "no version named means no conditional save")
	assert.Equal(t, Version{OIDC: 4, App: 7}, ap.expected.Version, "and the request's own read still guards the write")
}

// A version the server did not issue is refused, and nothing is written. Reading it as "no version" would silently promote the
// caller's conditional save to an overwrite: the save would succeed, and the caller would believe it had been checked.
// spec:sso-configuration/a-save-can-name-the-configuration-it-was-editing/a-version-supplied-with-no-value-is-refused
func TestHandleUpdate_anUnreadableVersionIsRefusedWithoutWriting(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		sent string
	}{
		{"present but empty, which is a client with a version field and nothing in it", ""},
		{"one part", "3"},
		{"first part is not a number", "x.1"},
		{"three parts", "1.2.3"},
		{"negative", "-1.0"},
		{"signed, which this never issues", "+1.2"},
		{"zero-padded, which this never issues", "01.2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ap := &captureApply{}
			h := NewHandler(okStoreCfg(), noopRead, ap.fn, allowAuthZ{}, &captureAudit{}, okProbe, nil)
			body := validUpdateBody()
			body.Version = &tc.sent
			w := httptest.NewRecorder()
			h.handleUpdate(w, putReq(t, body))
			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.False(t, ap.called, "an unreadable version must not reach the write as an overwrite")
		})
	}
}

// An omitted field and a present-but-empty one mean opposite things, and the string zero value cannot carry both. The empty case is
// covered above as a refusal; this is the other half, that a genuinely absent field still overwrites.
func TestHandleUpdate_anAbsentVersionFieldIsNotAnEmptyOne(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"the field is absent":    `{"issuer":"https://idp.example.com","client_id":"cid","external_url":"https://edr.example.com","scopes":["openid"],"jit_enabled":true,"default_role":"analyst"}`,
		"the field is JSON null": `{"issuer":"https://idp.example.com","client_id":"cid","external_url":"https://edr.example.com","scopes":["openid"],"jit_enabled":true,"default_role":"analyst","version":null}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ap := &captureApply{}
			h := NewHandler(okStoreCfg(), noopRead, ap.fn, allowAuthZ{}, &captureAudit{}, okProbe, nil)
			r := withActor(httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/settings/sso", strings.NewReader(raw)), 42)
			w := httptest.NewRecorder()
			h.handleUpdate(w, r)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			require.True(t, ap.called)
			assert.False(t, ap.expected.Checked, "nothing to check against, so the save overwrites as a script expects")
		})
	}
}

// Either stored part having moved on is the same answer to the caller: nothing was saved. The two are separate tables with separate
// counters, and a handler that mapped only one of them would report the other as a server error, which reads as "try again" rather
// than "reload and look at what changed".
func TestHandleUpdate_eitherPartsConflictIsA409(t *testing.T) {
	t.Parallel()
	cases := map[string]error{
		"the deployment settings moved on": appconfig.ErrVersionConflict,
		"the OIDC configuration moved on":  ssoconfig.ErrVersionConflict,
	}
	for name, conflict := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ap := &captureApply{err: conflict}
			h := NewHandler(okStoreCfg(), noopRead, ap.fn, allowAuthZ{}, &captureAudit{}, okProbe, nil)
			body := validUpdateBody()
			body.Version = new(Version{OIDC: 1, App: 1}.String())
			w := httptest.NewRecorder()
			h.handleUpdate(w, putReq(t, body))
			assert.Equal(t, http.StatusConflict, w.Code)
			assert.Contains(t, w.Body.String(), "version_conflict")
		})
	}
}

// The read reports the version of what it read, and an unconfigured deployment reports one too. A client with no version to send
// could only overwrite, which is exactly the race a first save needs closed.
func TestHandleGet_reportsTheVersionOfWhatItRead(t *testing.T) {
	t.Parallel()
	cases := map[string]*fakeRead{
		"configured":   {cfg: &ssoconfig.Config{Issuer: "https://idp", ClientID: "cid"}, version: Version{OIDC: 3, App: 8}},
		"unconfigured": {version: Version{App: 2}},
	}
	for name, read := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := NewHandler(&fakeStore{}, read.fn, noopApply, allowAuthZ{}, &captureAudit{}, okProbe, nil)
			w := httptest.NewRecorder()
			h.handleGet(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/settings/sso", nil))
			require.Equal(t, http.StatusOK, w.Code)
			var resp configResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.Equal(t, read.version.String(), resp.Version)
		})
	}
}

// The saved response carries what the write read back inside its own transaction, not what a read afterwards would find. A re-read
// can be overtaken by the next writer, and the caller would be handed a version that does not describe the values beside it: send
// that version back and the check passes while the caller holds someone else's configuration.
func TestHandleUpdate_reportsTheVersionTheWriteRead(t *testing.T) {
	t.Parallel()
	ap := &captureApply{saved: Snapshot{
		Config:    &ssoconfig.Config{Issuer: "https://saved.example.com", ClientID: "saved"},
		AppConfig: appconfig.AppConfig{ExternalURL: "https://saved.example.com"},
		Version:   Version{OIDC: 5, App: 9},
	}}
	// A read reporting something else, so a response built from it rather than from the write would be visibly wrong.
	read := &fakeRead{cfg: &ssoconfig.Config{Issuer: "https://stale", ClientID: "stale"}, version: Version{OIDC: 1, App: 1}}
	h := NewHandler(okStoreCfg(), read.fn, ap.fn, allowAuthZ{}, &captureAudit{}, okProbe, nil)

	w := httptest.NewRecorder()
	h.handleUpdate(w, putReq(t, validUpdateBody()))

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp configResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "5.9", resp.Version)
	assert.Equal(t, "https://saved.example.com", resp.Issuer, "and the values the version describes")
}
