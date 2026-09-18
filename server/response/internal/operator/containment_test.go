package operator

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/response/api"
)

// fakeContainment records what the handler asked of the containment service and answers with set values.
type fakeContainment struct {
	list   []api.ContainmentState
	state  api.ContainmentState
	change api.ContainmentChange
	err    error
	calls  []string
	actor  identityapi.PrincipalRef
	// expected is the version the request named, so a test can assert the handler passed it through rather than dropping it.
	expected *int64
	getErr   error
}

func (f *fakeContainment) List(context.Context) ([]api.ContainmentState, error) {
	f.calls = append(f.calls, "list")
	return f.list, f.err
}

func (f *fakeContainment) Get(_ context.Context, hostID string) (api.ContainmentState, error) {
	f.calls = append(f.calls, "get "+hostID)
	// getErr rather than err, so a test can make a read fail while a change succeeds, and the other way round.
	return f.state, f.getErr
}

func (f *fakeContainment) Set(_ context.Context, actor identityapi.PrincipalRef, _, hostID string, contained bool, reason string,
	expected *int64) (api.ContainmentChange, error) {
	f.actor = actor
	f.expected = expected
	f.calls = append(f.calls, "set "+hostID+" "+map[bool]string{true: "contain", false: "release"}[contained]+" "+reason)
	return f.change, f.err
}

// recordingAuthZ records each decision it is asked for and answers with allow.
type recordingAuthZ struct {
	allow     bool
	decisions []string
}

func (r *recordingAuthZ) Allow(_ context.Context, action identityapi.Action, resource identityapi.Resource) (identityapi.Decision, error) {
	r.decisions = append(r.decisions, string(action)+" "+resource.Type+":"+resource.ID)
	return identityapi.Decision{Allow: r.allow, Reason: "test"}, nil
}

func serveContainment(t *testing.T, svc ContainmentService, authz identityapi.AuthZ, method, path, body string) *http.Response {
	t.Helper()
	mux := http.NewServeMux()
	NewContainmentHandler(svc, authz, slog.Default()).RegisterRoutes(mux)
	actor := &identityapi.Actor{Principal: identityapi.PrincipalRef{ID: "user:7", Type: "user"}}
	withActor := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r.WithContext(identityapi.WithActor(r.Context(), actor)))
	})
	srv := httptest.NewServer(withActor)
	t.Cleanup(srv.Close)
	req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+path, strings.NewReader(body))
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	return resp
}

func errorCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &body), string(raw))
	return body.Error
}

func TestContainmentHandler_Set(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		body       string
		svcErr     error
		wantStatus int
		wantError  string
		wantCall   string
	}{
		{name: "contain", body: `{"contained":true,"reason":"beaconing"}`, wantStatus: http.StatusOK, wantCall: "set host-a contain beaconing"},
		{name: "release", body: `{"contained":false,"reason":"reimaged"}`, wantStatus: http.StatusOK, wantCall: "set host-a release reimaged"},
		{name: "no contained", body: `{"reason":"beaconing"}`, wantStatus: http.StatusBadRequest, wantError: "bad_body"},
		{name: "not JSON", body: `{`, wantStatus: http.StatusBadRequest, wantError: "bad_body"},
		{name: "a body over the cap", body: `{"contained":true,"reason":"` + strings.Repeat("x", containmentBodyCap) + `"}`,
			wantStatus: http.StatusRequestEntityTooLarge, wantError: "body_too_large"},
		{name: "data after the object", body: `{"contained":true,"reason":"x"}{}`, wantStatus: http.StatusBadRequest, wantError: "bad_body"},
		{name: "a second object", body: `{"contained":true,"reason":"x"} {"contained":false}`, wantStatus: http.StatusBadRequest,
			wantError: "bad_body"},
		{name: "a missing reason", body: `{"contained":true}`, svcErr: api.ErrContainmentReasonRequired,
			wantStatus: http.StatusBadRequest, wantError: "reason_required", wantCall: "set host-a contain "},
		{name: "a long reason", body: `{"contained":true,"reason":"x"}`, svcErr: api.ErrContainmentReasonTooLong,
			wantStatus: http.StatusBadRequest, wantError: "reason_too_long", wantCall: "set host-a contain x"},
		{name: "an unenrolled host", body: `{"contained":true,"reason":"x"}`, svcErr: api.ErrContainmentHostNotFound,
			wantStatus: http.StatusNotFound, wantError: "host_not_found", wantCall: "set host-a contain x"},
		{name: "a store failure", body: `{"contained":true,"reason":"x"}`, svcErr: errors.New("db down"),
			wantStatus: http.StatusInternalServerError, wantError: "internal", wantCall: "set host-a contain x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc := &fakeContainment{err: tc.svcErr, change: api.ContainmentChange{
				State: api.ContainmentState{HostID: "host-a", Contained: true, Version: 3}, Changed: true, CommandID: 9}}
			authz := &recordingAuthZ{allow: true}
			resp := serveContainment(t, svc, authz, http.MethodPost, "/api/hosts/host-a/containment", tc.body)
			defer resp.Body.Close()
			assert.Equal(t, tc.wantStatus, resp.StatusCode)
			assert.Equal(t, []string{"host.isolate host:host-a"}, authz.decisions)
			if tc.wantCall == "" {
				assert.Empty(t, svc.calls)
			} else {
				assert.Equal(t, []string{tc.wantCall}, svc.calls)
				assert.Equal(t, "user:7", svc.actor.ID, "the change is attributed to the authenticated actor")
			}
			if tc.wantError != "" {
				assert.Equal(t, tc.wantError, errorCode(t, resp))
				return
			}
			var got api.ContainmentChange
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
			assert.Equal(t, svc.change, got)
		})
	}
}

func TestContainmentHandler_List(t *testing.T) {
	t.Parallel()
	t.Run("returns every host with a state", func(t *testing.T) {
		t.Parallel()
		svc := &fakeContainment{list: []api.ContainmentState{{HostID: "host-a", Contained: true, Version: 1}}}
		authz := &recordingAuthZ{allow: true}
		resp := serveContainment(t, svc, authz, http.MethodGet, "/api/containment", "")
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, []string{"host.read host:"}, authz.decisions)
		var got struct {
			Items []api.ContainmentState `json:"items"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		assert.Equal(t, svc.list, got.Items)
	})
	t.Run("a read failure", func(t *testing.T) {
		t.Parallel()
		resp := serveContainment(t, &fakeContainment{err: errors.New("db down")}, &recordingAuthZ{allow: true}, http.MethodGet,
			"/api/containment", "")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

func TestContainmentHandler_Get(t *testing.T) {
	t.Parallel()
	t.Run("returns the state", func(t *testing.T) {
		t.Parallel()
		svc := &fakeContainment{state: api.ContainmentState{HostID: "host-a", Contained: true, Version: 2}}
		authz := &recordingAuthZ{allow: true}
		resp := serveContainment(t, svc, authz, http.MethodGet, "/api/hosts/host-a/containment", "")
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, []string{"host.read host:host-a"}, authz.decisions)
		var got api.ContainmentState
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		assert.Equal(t, svc.state, got)
	})
	t.Run("a read failure", func(t *testing.T) {
		t.Parallel()
		svc := &fakeContainment{getErr: errors.New("db down")}
		resp := serveContainment(t, svc, &recordingAuthZ{allow: true}, http.MethodGet, "/api/hosts/host-a/containment", "")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		assert.Equal(t, "internal", errorCode(t, resp))
	})
}

// Both routes are gated: a denied caller changes and reads nothing.
func TestContainmentHandler_DeniedCallersReachNothing(t *testing.T) {
	t.Parallel()
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/api/containment"},
		{http.MethodGet, "/api/hosts/host-a/containment"},
		{http.MethodPost, "/api/hosts/host-a/containment"},
	} {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			t.Parallel()
			svc := &fakeContainment{}
			resp := serveContainment(t, svc, &recordingAuthZ{allow: false}, route.method, route.path, `{"contained":true,"reason":"x"}`)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
			assert.Empty(t, svc.calls)
		})
	}
}

// FuzzContainmentHandler_Set feeds arbitrary request bodies to the containment route: it must not panic, and every body is either
// refused as malformed or handed to the service with a definite contained value.
func FuzzContainmentHandler_Set(f *testing.F) {
	f.Add(`{"contained":true,"reason":"beaconing"}`)
	f.Add(`{"contained":null}`)
	f.Add(`{"reason":7}`)
	f.Add(`[`)
	f.Fuzz(func(t *testing.T, body string) {
		svc := &fakeContainment{}
		h := NewContainmentHandler(svc, &recordingAuthZ{allow: true}, slog.New(slog.DiscardHandler))
		mux := http.NewServeMux()
		h.RegisterRoutes(mux)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/hosts/host-a/containment", strings.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		switch rec.Code {
		case http.StatusOK:
			if len(svc.calls) != 1 {
				t.Fatalf("a 200 without exactly one change: %q", body)
			}
			// A body that changed a host is one JSON object and nothing more.
			dec := json.NewDecoder(strings.NewReader(body))
			var first, second json.RawMessage
			if dec.Decode(&first) != nil || !errors.Is(dec.Decode(&second), io.EOF) {
				t.Fatalf("a body that is not exactly one JSON value changed a host: %q", body)
			}
		case http.StatusBadRequest, http.StatusRequestEntityTooLarge:
			if len(svc.calls) != 0 {
				t.Fatalf("a malformed body reached the service: %q", body)
			}
		default:
			t.Fatalf("unexpected status %d for %q", rec.Code, body)
		}
	})
}

// spec:server-host-containment/an-operator-contains-or-releases-a-host/a-change-naming-a-version-the-host-has-moved-past-is-refused
//
// The route carries the version the caller read, and reports a conflict with the state as it now stands, so the console can say what
// changed rather than making another request to find out (issue #1076).
func TestContainmentHandler_AVersionConflictIsReportedWithTheCurrentState(t *testing.T) {
	t.Parallel()
	current := api.ContainmentState{HostID: "host-a", Contained: false, Version: 4, Reason: "cleared by someone else"}
	svc := &fakeContainment{err: api.ErrContainmentVersionConflict, change: api.ContainmentChange{State: current}}

	resp := serveContainment(t, svc, &recordingAuthZ{allow: true}, http.MethodPost, "/api/hosts/host-a/containment",
		`{"contained":true,"reason":"beaconing","expected_version":1}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusConflict, resp.StatusCode)

	var body struct {
		Error string               `json:"error"`
		State api.ContainmentState `json:"state"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "version_conflict", body.Error)
	assert.Equal(t, current, body.State, "the state the caller has to decide from, without asking again")
	require.NotNil(t, svc.expected)
	assert.Equal(t, int64(1), *svc.expected, "the version the request named reached the service")
}

// A request that names no version reaches the service with none, which is what every caller did before this and still does.
func TestContainmentHandler_ARequestWithoutAVersionNamesNone(t *testing.T) {
	t.Parallel()
	svc := &fakeContainment{change: api.ContainmentChange{State: api.ContainmentState{HostID: "host-a", Contained: true, Version: 1}}}

	resp := serveContainment(t, svc, &recordingAuthZ{allow: true}, http.MethodPost, "/api/hosts/host-a/containment",
		`{"contained":true,"reason":"beaconing"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Nil(t, svc.expected)
}

// The conflict answers from the refusal itself and never reads the host again, which is what lets the schema require the state on
// every version conflict. A handler that re-read would answer with whatever landed after the refusal, and would have to invent an
// answer when that read failed: here the read is made to fail and the state arrives whole regardless.
func TestContainmentHandler_AVersionConflictIsAnsweredWithoutASecondRead(t *testing.T) {
	t.Parallel()
	current := api.ContainmentState{HostID: "host-a", Contained: true, Version: 9, Reason: "contained by someone else"}
	svc := &fakeContainment{
		err:    api.ErrContainmentVersionConflict,
		change: api.ContainmentChange{State: current},
		state:  api.ContainmentState{HostID: "host-a", Version: 11, Reason: "a change that landed after the refusal"},
		getErr: errors.New("db down"),
	}

	resp := serveContainment(t, svc, &recordingAuthZ{allow: true}, http.MethodPost, "/api/hosts/host-a/containment",
		`{"contained":true,"reason":"beaconing","expected_version":1}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusConflict, resp.StatusCode)

	var body struct {
		State api.ContainmentState `json:"state"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, current, body.State, "the state the refusal was decided against, not one read after it")
	assert.Equal(t, []string{"set host-a contain beaconing"}, svc.calls, "the conflict asked the service nothing further")
}
