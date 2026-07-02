package operator

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	identityapi "github.com/fleetdm/edr/server/identity/api"
)

type fakeHostDetail struct {
	fn func(ctx context.Context, hostID string) (api.HostDetail, error)
}

func (f fakeHostDetail) HostDetail(ctx context.Context, hostID string) (api.HostDetail, error) {
	return f.fn(ctx, hostID)
}

// newHostDetailServer builds the operator handler with a fake api.Service (the detail route never touches it) and optionally installs
// the host-detail seam, mirroring newHostHealthServer.
func newHostDetailServer(t *testing.T, hd HostDetailReader, az identityapi.AuthZ) *httptest.Server {
	t.Helper()
	h := New(fakeService{}, az, slog.Default())
	if hd != nil {
		h.SetHostDetail(hd)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// spec:server-rest-api/host-detail-endpoint/operator-fetches-host-detail
func TestHandleHostDetail_Success(t *testing.T) {
	t.Parallel()
	var gotHostID string
	hd := fakeHostDetail{fn: func(_ context.Context, hostID string) (api.HostDetail, error) {
		gotHostID = hostID
		return api.HostDetail{
			HostID: hostID, Hostname: "mac-01.local", OSName: "macOS", OSVersion: "26.4", OSBuild: "25E123",
			AgentVersion: "0.5.0", SourceIP: "192.0.2.10", EnrolledAtNs: 1_700_000_000_000_000_000,
			InventoryReportedAtNs: 42, EventCount: 7, LastSeenNs: 99, OverallStatus: "healthy",
		}, nil
	}}
	srv := newHostDetailServer(t, hd, allowAllAuthZ{})

	resp := doGet(t, srv, "/api/hosts/host-a")
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "host-a", gotHostID)
	var got api.HostDetail
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, "mac-01.local", got.Hostname)
	assert.Equal(t, "macOS", got.OSName)
	assert.Equal(t, "26.4", got.OSVersion)
	assert.Equal(t, "25E123", got.OSBuild)
	assert.Equal(t, "0.5.0", got.AgentVersion)
	assert.Equal(t, "192.0.2.10", got.SourceIP)
	assert.EqualValues(t, 7, got.EventCount)
	assert.Equal(t, "healthy", got.OverallStatus)
}

// spec:server-rest-api/host-detail-endpoint/unknown-host-id-returns-404
func TestHandleHostDetail_UnknownHost404(t *testing.T) {
	t.Parallel()
	hd := fakeHostDetail{fn: func(context.Context, string) (api.HostDetail, error) {
		return api.HostDetail{}, sql.ErrNoRows
	}}
	srv := newHostDetailServer(t, hd, allowAllAuthZ{})

	resp := doGet(t, srv, "/api/hosts/nope")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestHandleHostDetail_UnwiredIs503(t *testing.T) {
	t.Parallel()
	srv := newHostDetailServer(t, nil, allowAllAuthZ{})

	resp := doGet(t, srv, "/api/hosts/host-a")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestHandleHostDetail_DeniedByAuthz(t *testing.T) {
	t.Parallel()
	hd := fakeHostDetail{fn: func(context.Context, string) (api.HostDetail, error) {
		t.Fatal("reader must not be reached when authz denies")
		return api.HostDetail{}, nil
	}}
	srv := newHostDetailServer(t, hd, denyAllAuthZ{})

	resp := doGet(t, srv, "/api/hosts/host-a")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}
