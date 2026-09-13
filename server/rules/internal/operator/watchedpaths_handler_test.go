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
}

func (f *fakeWatchedPaths) Get(context.Context) (api.WatchedPathSet, error) { return f.set, f.getErr }

func (f *fakeWatchedPaths) Replace(_ context.Context, actor *identityapi.Actor, reason string, paths []api.WatchedPath) (
	watchedpaths.ReplaceResult, error) {
	f.gotActor, f.gotReason, f.gotPaths = actor, reason, paths
	if f.replaceErr != nil {
		return watchedpaths.ReplaceResult{}, f.replaceErr
	}
	return watchedpaths.ReplaceResult{Set: api.WatchedPathSet{Version: 4, Paths: paths}, FanoutHosts: 3, FanoutFailed: 1}, nil
}

var _ watchedPathsService = (*watchedpaths.Service)(nil)

func watchedPathsServer(t *testing.T, svc watchedPathsService, withActor bool) *httptest.Server {
	t.Helper()
	h := NewDetectionConfig(&fakeDCService{}, allowAllAuthZ{}, slog.Default())
	h.SetWatchedPaths(svc)
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
	svc := &fakeWatchedPaths{set: api.WatchedPathSet{Version: 2, Paths: []api.WatchedPath{{Path: "/Library/StartupItems/", Match: "prefix"}}}}
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
		{"invalid set", fmt.Errorf("%w: entry 0 (%q): a prefix must lie below a top-level directory", api.ErrInvalidWatchedPaths, "/Users/"),
			http.StatusBadRequest, "below a top-level directory"},
		{"store failure", errors.New("database unavailable"), http.StatusInternalServerError, "internal error"},
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

func TestWatchedPathsHandler_GetFailureIs500(t *testing.T) {
	t.Parallel()
	resp := dcDo(t, watchedPathsServer(t, &fakeWatchedPaths{getErr: errors.New("boom")}, true), http.MethodGet,
		"/api/v1/detection-config/watched-paths", "")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestWatchedPathsHandler_ReplaceRejectsABadBodyAndAMissingActor(t *testing.T) {
	t.Parallel()
	svc := &fakeWatchedPaths{}
	bad := dcDo(t, watchedPathsServer(t, svc, true), http.MethodPut, "/api/v1/detection-config/watched-paths", `{`)
	bad.Body.Close()
	assert.Equal(t, http.StatusBadRequest, bad.StatusCode)

	noList := dcDo(t, watchedPathsServer(t, svc, true), http.MethodPut, "/api/v1/detection-config/watched-paths", `{"reason":"r"}`)
	noList.Body.Close()
	assert.Equal(t, http.StatusBadRequest, noList.StatusCode)

	noActor := dcDo(t, watchedPathsServer(t, svc, false), http.MethodPut, "/api/v1/detection-config/watched-paths", `{"paths":[],"reason":"r"}`)
	noActor.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, noActor.StatusCode)
	assert.Nil(t, svc.gotActor, "neither request reaches the service")
}

// Without the command queue and host list the push needs, the routes are not offered at all rather than failing on use.
func TestWatchedPathsHandler_RoutesAbsentWithoutTheService(t *testing.T) {
	t.Parallel()
	srv := dcServer(t, &fakeDCService{}, true)
	resp := dcDo(t, srv, http.MethodGet, "/api/v1/detection-config/watched-paths", "")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}
