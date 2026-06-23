package operator

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/detectionconfig"
)

// denyAllAuthZ forces the HTTPGate deny branch so the per-handler 403 path is covered.
type denyAllAuthZ struct{}

func (denyAllAuthZ) Allow(context.Context, identityapi.Action, identityapi.Resource) (identityapi.Decision, error) {
	return identityapi.Decision{Allow: false, Reason: "no_matching_rule"}, nil
}

// fakeDCService is an in-memory detectionConfigService for handler tests: it returns canned results, or a canned error to drive the
// handler's error branches, and records the last (reason, actor) so the actor/reason plumbing can be asserted.
type fakeDCService struct {
	exclusions []api.DetectionExclusion
	settings   []api.DetectionRuleSetting
	created    api.DetectionExclusion
	setting    api.DetectionRuleSetting
	listErr    error
	createErr  error
	deleteErr  error
	upsertErr  error
	lastReason string
	lastActor  *identityapi.Actor
}

func (f *fakeDCService) ListExclusions(context.Context) ([]api.DetectionExclusion, error) {
	return f.exclusions, f.listErr
}

func (f *fakeDCService) ListRuleSettings(context.Context) ([]api.DetectionRuleSetting, error) {
	return f.settings, f.listErr
}

func (f *fakeDCService) CreateExclusion(_ context.Context, actor *identityapi.Actor, reason string, _ detectionconfig.CreateExclusionInput) (api.DetectionExclusion, error) {
	f.lastReason, f.lastActor = reason, actor
	return f.created, f.createErr
}

func (f *fakeDCService) DeleteExclusion(_ context.Context, actor *identityapi.Actor, reason string, _ int64) error {
	f.lastReason, f.lastActor = reason, actor
	return f.deleteErr
}

func (f *fakeDCService) UpsertRuleSetting(_ context.Context, actor *identityapi.Actor, reason string, _ detectionconfig.UpsertSettingInput) (api.DetectionRuleSetting, error) {
	f.lastReason, f.lastActor = reason, actor
	return f.setting, f.upsertErr
}

// dcServer mounts the handler behind allow-all authz + an actor-injecting middleware (standing in for the session middleware) and
// returns an httptest server. withActor=false omits the actor so the no-actor 500 path can be exercised.
func dcServer(t *testing.T, svc detectionConfigService, withActor bool) *httptest.Server {
	t.Helper()
	h := NewDetectionConfig(svc, allowAllAuthZ{}, slog.Default())
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	var handler http.Handler = mux
	if withActor {
		inner := handler
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := identityapi.WithActor(r.Context(), &identityapi.Actor{UserID: 7, SessionFresh: true})
			inner.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func dcDo(t *testing.T, srv *httptest.Server, method, path, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+path, strings.NewReader(body))
	require.NoError(t, err)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	return resp
}

// mountDC mounts the handler behind allow-all authz + an actor-injecting middleware so the list path runs with an actor on ctx.
func mountDC(t *testing.T, h *DetectionConfigHandler) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := identityapi.WithActor(r.Context(), &identityapi.Actor{UserID: 7, SessionFresh: true})
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func TestDetectionConfigHandler_ResolvesCreatedByEmail(t *testing.T) {
	t.Parallel()
	exclusions := []api.DetectionExclusion{
		{ID: 1, CreatedBy: "user:8"},                 // resolves
		{ID: 2, CreatedBy: "user:8"},                 // same author: memoized, no second lookup
		{ID: 3, CreatedBy: "user:9"},                 // resolver errors: email stays empty
		{ID: 4, CreatedBy: "service-account:reaper"}, // non-user actor: never looked up
	}

	t.Run("fills email, memoizes per id, falls back on error or non-user actor", func(t *testing.T) {
		t.Parallel()
		var calls int
		h := NewDetectionConfig(&fakeDCService{exclusions: exclusions}, allowAllAuthZ{}, slog.Default())
		h.SetUserEmailResolver(func(_ context.Context, id int64) (string, error) {
			calls++
			if id == 8 {
				return "ops@fleetdm.com", nil
			}
			return "", errors.New("user not found")
		})
		srv := mountDC(t, h)
		resp := dcDo(t, srv, http.MethodGet, "/api/v1/detection-config/exclusions", "")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var out struct {
			Exclusions []api.DetectionExclusion `json:"exclusions"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
		resp.Body.Close()

		require.Len(t, out.Exclusions, 4)
		assert.Equal(t, "ops@fleetdm.com", out.Exclusions[0].CreatedByEmail)
		assert.Equal(t, "ops@fleetdm.com", out.Exclusions[1].CreatedByEmail)
		assert.Empty(t, out.Exclusions[2].CreatedByEmail, "errored lookup leaves email blank")
		assert.Empty(t, out.Exclusions[3].CreatedByEmail, "non-user actor is not looked up")
		assert.Equal(t, 2, calls, "user:8 resolved once (memoized) + user:9 once; service-account skipped")
	})

	t.Run("nil resolver leaves created_by_email empty", func(t *testing.T) {
		t.Parallel()
		h := NewDetectionConfig(&fakeDCService{exclusions: exclusions}, allowAllAuthZ{}, slog.Default())
		srv := mountDC(t, h)
		resp := dcDo(t, srv, http.MethodGet, "/api/v1/detection-config/exclusions", "")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var out struct {
			Exclusions []api.DetectionExclusion `json:"exclusions"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
		resp.Body.Close()
		for _, ex := range out.Exclusions {
			assert.Empty(t, ex.CreatedByEmail)
		}
	})
}

func TestDetectionConfigHandler_Reads(t *testing.T) {
	t.Parallel()
	t.Run("list exclusions + settings ok", func(t *testing.T) {
		t.Parallel()
		svc := &fakeDCService{
			exclusions: []api.DetectionExclusion{{ID: 1, RuleID: "suspicious_exec", MatchType: api.ExclusionMatchParentPathGlob, Value: "*/x/*"}},
			settings:   []api.DetectionRuleSetting{{RuleID: "suspicious_exec", Mode: api.DetectionRuleModeDisabled}},
		}
		srv := dcServer(t, svc, true)
		resp := dcDo(t, srv, http.MethodGet, "/api/v1/detection-config/exclusions", "")
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
		resp = dcDo(t, srv, http.MethodGet, "/api/v1/detection-config/rule-settings", "")
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("list errors surface as 500", func(t *testing.T) {
		t.Parallel()
		srv := dcServer(t, &fakeDCService{listErr: errors.New("db down")}, true)
		resp := dcDo(t, srv, http.MethodGet, "/api/v1/detection-config/exclusions", "")
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		resp.Body.Close()
		resp = dcDo(t, srv, http.MethodGet, "/api/v1/detection-config/rule-settings", "")
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestDetectionConfigHandler_CreateExclusion(t *testing.T) {
	t.Parallel()
	goodBody := `{"rule_id":"suspicious_exec","match_type":"parent_path_glob","value":"*/claude/versions/*","reason":"Claude"}`
	cases := []struct {
		name   string
		body   string
		svc    *fakeDCService
		status int
	}{
		{"created", goodBody, &fakeDCService{created: api.DetectionExclusion{ID: 9}}, http.StatusCreated},
		{"invalid json", `{not json`, &fakeDCService{}, http.StatusBadRequest},
		{"missing reason", `{"rule_id":"x","match_type":"team_id","value":"ABC"}`, &fakeDCService{}, http.StatusBadRequest},
		{"group scope rejected", `{"rule_id":"x","match_type":"team_id","value":"ABC","host_group_id":5,"reason":"r"}`, &fakeDCService{}, http.StatusBadRequest},
		{"service invalid-request is 400", goodBody, &fakeDCService{createErr: detectionconfig.ErrInvalidRequest}, http.StatusBadRequest},
		{"service internal is 500", goodBody, &fakeDCService{createErr: errors.New("boom")}, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := dcServer(t, tc.svc, true)
			resp := dcDo(t, srv, http.MethodPost, "/api/v1/detection-config/exclusions", tc.body)
			assert.Equal(t, tc.status, resp.StatusCode)
			resp.Body.Close()
		})
	}
}

func TestDetectionConfigHandler_DeleteExclusion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		path   string
		svc    *fakeDCService
		status int
	}{
		{"deleted", "/api/v1/detection-config/exclusions/9?reason=resolved", &fakeDCService{}, http.StatusNoContent},
		{"invalid id", "/api/v1/detection-config/exclusions/abc?reason=r", &fakeDCService{}, http.StatusBadRequest},
		{"missing reason", "/api/v1/detection-config/exclusions/9", &fakeDCService{}, http.StatusBadRequest},
		{"not found", "/api/v1/detection-config/exclusions/9?reason=r", &fakeDCService{deleteErr: sql.ErrNoRows}, http.StatusNotFound},
		{"service internal is 500", "/api/v1/detection-config/exclusions/9?reason=r", &fakeDCService{deleteErr: errors.New("boom")}, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := dcServer(t, tc.svc, true)
			resp := dcDo(t, srv, http.MethodDelete, tc.path, "")
			assert.Equal(t, tc.status, resp.StatusCode)
			resp.Body.Close()
		})
	}
}

func TestDetectionConfigHandler_UpsertRuleSetting(t *testing.T) {
	t.Parallel()
	goodBody := `{"rule_id":"suspicious_exec","mode":"disabled","reason":"noisy"}`
	cases := []struct {
		name   string
		body   string
		svc    *fakeDCService
		status int
	}{
		{"ok", goodBody, &fakeDCService{setting: api.DetectionRuleSetting{RuleID: "suspicious_exec", Mode: api.DetectionRuleModeDisabled}}, http.StatusOK},
		{"invalid json", `{`, &fakeDCService{}, http.StatusBadRequest},
		{"missing reason", `{"rule_id":"x","mode":"alert"}`, &fakeDCService{}, http.StatusBadRequest},
		{"group scope rejected", `{"rule_id":"x","mode":"alert","host_group_id":5,"reason":"r"}`, &fakeDCService{}, http.StatusBadRequest},
		{"service invalid-request is 400", goodBody, &fakeDCService{upsertErr: detectionconfig.ErrInvalidRequest}, http.StatusBadRequest},
		{"service internal is 500", goodBody, &fakeDCService{upsertErr: errors.New("boom")}, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := dcServer(t, tc.svc, true)
			resp := dcDo(t, srv, http.MethodPut, "/api/v1/detection-config/rule-settings", tc.body)
			assert.Equal(t, tc.status, resp.StatusCode)
			resp.Body.Close()
		})
	}
}

func TestDetectionConfigHandler_MissingActorIs500(t *testing.T) {
	t.Parallel()
	// No actor middleware: a write that clears the gate + decode + reason validation hits the missing-actor guard and 500s.
	srv := dcServer(t, &fakeDCService{}, false)
	resp := dcDo(t, srv, http.MethodPost, "/api/v1/detection-config/exclusions",
		`{"rule_id":"x","match_type":"team_id","value":"ABC","reason":"r"}`)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	resp.Body.Close()
}

func TestDetectionConfigHandler_AuthzDenyIs403(t *testing.T) {
	t.Parallel()
	h := NewDetectionConfig(&fakeDCService{}, denyAllAuthZ{}, slog.Default())
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	for _, ep := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/detection-config/exclusions", ""},
		{http.MethodGet, "/api/v1/detection-config/rule-settings", ""},
		{http.MethodPost, "/api/v1/detection-config/exclusions", `{}`},
		{http.MethodDelete, "/api/v1/detection-config/exclusions/1?reason=r", ""},
		{http.MethodPut, "/api/v1/detection-config/rule-settings", `{}`},
	} {
		resp := dcDo(t, srv, ep.method, ep.path, ep.body)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode, "%s %s must be forbidden", ep.method, ep.path)
		resp.Body.Close()
	}
}

func TestDetectionConfigHandler_ConstructorGuards(t *testing.T) {
	t.Parallel()
	assert.Panics(t, func() { NewDetectionConfig(nil, allowAllAuthZ{}, slog.Default()) })
	assert.Panics(t, func() { NewDetectionConfig(&fakeDCService{}, nil, slog.Default()) })
}

// _ ensures the concrete service satisfies the handler's narrow interface at compile time.
var _ detectionConfigService = (*detectionconfig.Service)(nil)
