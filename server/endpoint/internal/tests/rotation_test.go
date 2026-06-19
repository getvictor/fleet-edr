//go:build integration

package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/endpoint/bootstrap"
)

// refreshMux mounts POST /api/token/refresh behind the host-token middleware exactly as cmd/main does, so the test exercises the real
// auth + handler path end to end.
func refreshMux(ep *bootstrap.Endpoint) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("POST /api/token/refresh", ep.HostTokenMiddleware()(ep.TokenRefreshHandler()))
	return mux
}

func postRefresh(t *testing.T, ctx context.Context, srv *httptest.Server, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/api/token/refresh", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	return resp
}

// spec:agent-enrollment/agent-refreshes-its-token-before-expiry/refresh-issues-a-fresh-token
//
// TestTokenRefresh_HTTP walks the agent-pull refresh flow: a valid token yields a fresh, verifiable token; after the host is revoked
// (and the revocation snapshot refreshes) the same endpoint returns 401, which is what drives the agent's re-enroll path.
func TestTokenRefresh_HTTP(t *testing.T) {
	t.Parallel()
	ep := newEndpoint(t)
	ctx := t.Context()

	res, err := ep.Service().Enroll(ctx, api.EnrollRequest{
		EnrollSecret: testEnrollSecret,
		HardwareUUID: testHardwareUUID,
		Hostname:     "h",
		OSVersion:    "macOS 14",
		AgentVersion: "0.1.0",
	}, "192.0.2.1")
	require.NoError(t, err)

	srv := httptest.NewServer(refreshMux(ep))
	t.Cleanup(srv.Close)

	// Refresh with the current token returns a fresh, verifiable token.
	resp := postRefresh(t, ctx, srv, res.HostToken)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var refreshed api.RefreshResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&refreshed))
	resp.Body.Close()
	require.NotEmpty(t, refreshed.HostToken)
	assert.Equal(t, testHardwareUUID, refreshed.HostID)

	hostID, err := ep.Service().VerifyToken(ctx, refreshed.HostToken)
	require.NoError(t, err)
	assert.Equal(t, testHardwareUUID, hostID)

	// After revoke + snapshot refresh, the refresh endpoint rejects with 401.
	require.NoError(t, ep.Service().Revoke(ctx, testHardwareUUID, "compromised", "op"))
	require.NoError(t, ep.RevocationSnapshot().Refresh(ctx))
	resp = postRefresh(t, ctx, srv, refreshed.HostToken)
	resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestTokenRefresh_MissingBearer: no Authorization header is a 401 from the middleware, never reaching the handler.
func TestTokenRefresh_MissingBearer(t *testing.T) {
	t.Parallel()
	ep := newEndpoint(t)
	srv := httptest.NewServer(refreshMux(ep))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/token/refresh", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
