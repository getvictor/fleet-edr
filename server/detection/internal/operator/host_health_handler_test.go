package operator

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	identityapi "github.com/fleetdm/edr/server/identity/api"
)

type fakeHostHealth struct {
	fn func(ctx context.Context, hostID string) (api.HostHealth, error)
}

func (f fakeHostHealth) HostHealth(ctx context.Context, hostID string) (api.HostHealth, error) {
	return f.fn(ctx, hostID)
}

// newHostHealthServer builds the operator handler with a fake api.Service (the health route never touches it) and optionally installs
// the host-health seam, so tests can exercise both the wired and the not-configured paths.
func newHostHealthServer(t *testing.T, hh HostHealthReader, az identityapi.AuthZ) *httptest.Server {
	t.Helper()
	h := New(fakeService{}, az, slog.Default())
	if hh != nil {
		h.SetHostHealth(hh)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// spec:server-host-status/the-host-api-surfaces-per-host-health/the-host-detail-carries-the-component-conditions
func TestHandleHostHealth_Success(t *testing.T) {
	t.Parallel()
	var gotHostID string
	hh := fakeHostHealth{fn: func(_ context.Context, hostID string) (api.HostHealth, error) {
		gotHostID = hostID
		return api.HostHealth{
			OverallStatus: "unhealthy",
			ReportedAtNs:  42,
			Components:    api.NullRawJSON(`[{"type":"endpoint_security_extension","status":"unhealthy","reason":"never_connected"}]`),
		}, nil
	}}
	srv := newHostHealthServer(t, hh, allowAllAuthZ{})

	resp := doGet(t, srv, "/api/hosts/host-a/health")
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "host-a", gotHostID)
	var got api.HostHealth
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, "unhealthy", got.OverallStatus)
	assert.EqualValues(t, 42, got.ReportedAtNs)
	assert.Contains(t, string(got.Components), "never_connected")
}

func TestHandleHostHealth_AuthzDeny(t *testing.T) {
	t.Parallel()
	hh := fakeHostHealth{fn: func(context.Context, string) (api.HostHealth, error) {
		t.Fatal("reader must not be called when authz denies")
		return api.HostHealth{}, nil
	}}
	srv := newHostHealthServer(t, hh, denyAllAuthZ{})

	resp := doGet(t, srv, "/api/hosts/host-a/health")
	defer resp.Body.Close()
	assert.NotEqual(t, http.StatusOK, resp.StatusCode)
}

func TestHandleHostHealth_ReaderErrorMaps500(t *testing.T) {
	t.Parallel()
	hh := fakeHostHealth{fn: func(context.Context, string) (api.HostHealth, error) {
		return api.HostHealth{}, errors.New("db down")
	}}
	srv := newHostHealthServer(t, hh, allowAllAuthZ{})

	resp := doGet(t, srv, "/api/hosts/host-a/health")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Equal(t, errInternal, readErrorEnvelope(t, resp))
}

func TestHandleHostHealth_NotConfiguredMaps503(t *testing.T) {
	t.Parallel()
	srv := newHostHealthServer(t, nil, allowAllAuthZ{})

	resp := doGet(t, srv, "/api/hosts/host-a/health")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestHandleHostHealth_EmptyHostIDMaps400(t *testing.T) {
	t.Parallel()
	// The route pattern {host_id} never yields an empty segment through the mux, so drive the guard directly: a request with no path
	// value set has an empty host_id, which must 400 before the authz gate or the reader is consulted.
	h := New(fakeService{}, allowAllAuthZ{}, slog.Default())
	h.SetHostHealth(fakeHostHealth{fn: func(context.Context, string) (api.HostHealth, error) {
		t.Fatal("reader must not be called for an empty host_id")
		return api.HostHealth{}, nil
	}})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/hosts//health", nil)
	rec := httptest.NewRecorder()
	h.handleHostHealth(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	body, _ := io.ReadAll(rec.Result().Body)
	assert.Contains(t, string(body), errHostIDRequired)
}
