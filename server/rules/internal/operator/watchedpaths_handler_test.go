package operator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/watchedpaths"
)

type fakeWatchedPaths struct {
	set        api.WatchedPathSet
	getErr     error
	replaceErr error
	gotReason  string
	gotPaths   []api.WatchedPath
	gotActor   *identityapi.Actor
	gotExpect  *int64
}

func (f *fakeWatchedPaths) Get(context.Context) (api.WatchedPathSet, error) { return f.set, f.getErr }

func (f *fakeWatchedPaths) Replace(_ context.Context, actor *identityapi.Actor, reason string, paths []api.WatchedPath,
	expectedVersion *int64) (watchedpaths.ReplaceResult, error) {
	f.gotActor, f.gotReason, f.gotPaths, f.gotExpect = actor, reason, paths, expectedVersion
	if f.replaceErr != nil {
		return watchedpaths.ReplaceResult{}, f.replaceErr
	}
	set := api.WatchedPathSet{Version: 4, Paths: paths, UpdatedBy: actor.Principal.ID}
	return watchedpaths.ReplaceResult{Set: set, FanoutHosts: 3, FanoutFailed: 1}, nil
}

var _ watchedPathsService = (*watchedpaths.Service)(nil)

func watchedPathsServer(t *testing.T, svc watchedPathsService, withActor bool, opts ...func(*DetectionConfigHandler)) *httptest.Server {
	t.Helper()
	h := NewDetectionConfig(&fakeDCService{}, allowAllAuthZ{}, slog.Default())
	h.SetWatchedPaths(svc)
	for _, opt := range opts {
		opt(h)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	var handler http.Handler = mux
	if withActor {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := identityapi.WithActor(r.Context(), &identityapi.Actor{Principal: identityapi.UserPrincipal(7, "")})
			mux.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func TestWatchedPathsHandler_GetReportsTheSetBuiltInPathsAndBound(t *testing.T) {
	t.Parallel()
	set := api.WatchedPathSet{Version: 2, Paths: []api.WatchedPath{{Path: "/Library/StartupItems/", Match: "prefix"}}}
	svc := &fakeWatchedPaths{set: set}
	resp := dcDo(t, watchedPathsServer(t, svc, true), http.MethodGet, "/api/v1/detection-config/watched-paths", "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.EqualValues(t, 2, body["version"])
	assert.Equal(t, []any{map[string]any{"path": "/Library/StartupItems/", "match": "prefix"}}, body["paths"])
	assert.Equal(t, []any{
		map[string]any{"path": "/etc/sudoers", "match": "literal"},
		map[string]any{"path": "/etc/sudoers.d/", "match": "prefix"},
	}, body["built_in"])
	assert.EqualValues(t, api.MaxWatchedPaths, body["max_paths"])
}

func TestWatchedPathsHandler_ReplaceMapsEachOutcome(t *testing.T) {
	t.Parallel()
	body := `{"paths":[{"path":"/Library/StartupItems/","match":"prefix"}],"reason":"watch startup items"}`
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantInBody string
	}{
		{"stored", nil, http.StatusOK, `"fanout_failed":1`},
		{"no reason", watchedpaths.ErrReasonRequired, http.StatusBadRequest, "reason is required"},
		{
			"invalid set",
			fmt.Errorf("%w: entry 0 (%q): a prefix must lie below a top-level directory", api.ErrInvalidWatchedPaths, "/Users/"),
			http.StatusBadRequest, "below a top-level directory",
		},
		{"store failure", errors.New("database unavailable"), http.StatusInternalServerError, "internal error"},
		{
			"changed since read",
			fmt.Errorf("%w: it is at version 5, not 4", watchedpaths.ErrVersionConflict),
			http.StatusConflict, "at version 5, not 4",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc := &fakeWatchedPaths{replaceErr: tc.err}
			resp := dcDo(t, watchedPathsServer(t, svc, true), http.MethodPut, "/api/v1/detection-config/watched-paths", body)
			defer resp.Body.Close()
			assert.Equal(t, tc.wantStatus, resp.StatusCode)
			raw := new(bytes.Buffer)
			_, _ = raw.ReadFrom(resp.Body)
			assert.Contains(t, raw.String(), tc.wantInBody)
			assert.NotContains(t, raw.String(), "database unavailable", "a server error must not leak its cause")
			assert.Equal(t, "watch startup items", svc.gotReason)
			assert.Equal(t, []api.WatchedPath{{Path: "/Library/StartupItems/", Match: "prefix"}}, svc.gotPaths)
			assert.Equal(t, "usr_7", svc.gotActor.Principal.ID)
		})
	}
}

// spec:server-admin-surface/the-watched-path-set-names-who-last-changed-it/the-set-names-its-last-changer-by-label
// The console names who last changed the set, so both the read and the replace resolve updated_by to its display label, and leave it
// out when there is no one to name or the principal is gone.
func TestWatchedPathsHandler_ResolvesWhoLastChangedTheSet(t *testing.T) {
	t.Parallel()
	labels := func(t *testing.T) func(*DetectionConfigHandler) {
		t.Helper()
		return func(h *DetectionConfigHandler) {
			h.SetPrincipalLabelResolver(func(_ context.Context, id string) (string, error) {
				switch id {
				case "usr_7":
					return "ops@fleetdm.com", nil
				case "usr_9":
					return "", identityapi.ErrUserNotFound
				default:
					t.Errorf("resolved an unexpected principal %q", id)
					return "", errors.New("unexpected")
				}
			})
		}
	}
	changedBy := func(id string) api.WatchedPathSet {
		return api.WatchedPathSet{Version: 2, Paths: []api.WatchedPath{}, UpdatedBy: id}
	}
	cases := []struct {
		name      string
		method    string
		set       api.WatchedPathSet
		resolve   bool
		wantLabel any
	}{
		{"read names the principal", http.MethodGet, changedBy("usr_7"), true, "ops@fleetdm.com"},
		{"read of a deleted principal has no label", http.MethodGet, changedBy("usr_9"), true, nil},
		{"read of the set no one changed resolves nothing", http.MethodGet, api.WatchedPathSet{Paths: []api.WatchedPath{}}, true, nil},
		{"read without a resolver has no label", http.MethodGet, changedBy("usr_7"), false, nil},
		{"replace names the operator who made it", http.MethodPut, api.WatchedPathSet{}, true, "ops@fleetdm.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var opts []func(*DetectionConfigHandler)
			if tc.resolve {
				opts = append(opts, labels(t))
			}
			srv := watchedPathsServer(t, &fakeWatchedPaths{set: tc.set}, true, opts...)
			resp := dcDo(t, srv, tc.method, "/api/v1/detection-config/watched-paths", `{"paths":[],"reason":"r"}`)
			defer resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			var body map[string]any
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
			if tc.method == http.MethodPut {
				body, _ = body["set"].(map[string]any)
			}
			assert.Equal(t, tc.wantLabel, body["updated_by_label"])
		})
	}
}

// The version a client's edit started from reaches the service as sent, and its absence reaches it as no condition at all.
func TestWatchedPathsHandler_PassesTheExpectedVersionThrough(t *testing.T) {
	t.Parallel()
	startedFrom := int64(4)
	cases := []struct {
		name string
		body string
		want *int64
	}{
		{"named", `{"paths":[],"reason":"r","expected_version":4}`, &startedFrom},
		{"omitted", `{"paths":[],"reason":"r"}`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc := &fakeWatchedPaths{}
			resp := dcDo(t, watchedPathsServer(t, svc, true), http.MethodPut, "/api/v1/detection-config/watched-paths", tc.body)
			defer resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, tc.want, svc.gotExpect)
		})
	}
}

// The PUT body is the client's wire shape: every field, including a list that is present but empty and a version that is absent,
// survives Marshal then Unmarshal.
func TestReplaceWatchedPathsRequest_JSONRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		want := replaceWatchedPathsRequest{Reason: rapid.String().Draw(t, "reason")}
		if rapid.Bool().Draw(t, "has_paths") {
			paths := rapid.SliceOfN(rapid.Custom(func(t *rapid.T) api.WatchedPath {
				return api.WatchedPath{
					Path:  rapid.String().Draw(t, "path"),
					Match: rapid.SampledFrom([]api.WatchedPathMatch{api.WatchedPathLiteral, api.WatchedPathPrefix}).Draw(t, "match"),
				}
			}), 0, 8).Draw(t, "paths")
			want.Paths = &paths
		}
		if rapid.Bool().Draw(t, "has_expected_version") {
			version := rapid.Int64().Draw(t, "expected_version")
			want.ExpectedVersion = &version
		}
		b, err := json.Marshal(want)
		require.NoError(t, err)
		var got replaceWatchedPathsRequest
		require.NoError(t, json.Unmarshal(b, &got))
		assert.Equal(t, want, got)
	})
}

func TestWatchedPathsHandler_GetFailureIs500(t *testing.T) {
	t.Parallel()
	resp := dcDo(t, watchedPathsServer(t, &fakeWatchedPaths{getErr: errors.New("boom")}, true), http.MethodGet,
		"/api/v1/detection-config/watched-paths", "")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestWatchedPathsHandler_ReplaceRefusesBeforeTheService(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		withActor  bool
		body       string
		wantStatus int
	}{
		{"malformed JSON", true, `{`, http.StatusBadRequest},
		{"no paths list", true, `{"reason":"r"}`, http.StatusBadRequest},
		{"no actor on the context", false, `{"paths":[],"reason":"r"}`, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc := &fakeWatchedPaths{}
			resp := dcDo(t, watchedPathsServer(t, svc, tc.withActor), http.MethodPut, "/api/v1/detection-config/watched-paths", tc.body)
			resp.Body.Close()
			assert.Equal(t, tc.wantStatus, resp.StatusCode)
			assert.Nil(t, svc.gotActor, "the request does not reach the service")
		})
	}
}

// Without the command queue and host list the push needs, the routes are not offered at all rather than failing on use.
func TestWatchedPathsHandler_RoutesAbsentWithoutTheService(t *testing.T) {
	t.Parallel()
	srv := dcServer(t, &fakeDCService{}, true)
	resp := dcDo(t, srv, http.MethodGet, "/api/v1/detection-config/watched-paths", "")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}
