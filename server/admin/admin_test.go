package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/admin"
	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	endpointbootstrap "github.com/fleetdm/edr/server/endpoint/bootstrap"
	"github.com/fleetdm/edr/server/policy"
	"github.com/fleetdm/edr/server/store"
)

const (
	testUUID = "93DFC6F5-763D-5075-B305-8AC145D12F96"
	// #nosec G101 -- test fixture: not a real credential.
	testSecret = "admin-test-secret"
)

// newAdminServer wires the admin handler against a real test DB.
// Phase 2 of the modular-monolith migration removed the enrollment
// routes from admin (they live in server/endpoint/internal/operator/),
// so this helper only exercises the policy + rules + attack-coverage
// surfaces.
func newAdminServer(t *testing.T) (*httptest.Server, *endpointbootstrap.Endpoint, *store.Store) {
	t.Helper()
	s := store.OpenTestStore(t)
	endpointCtx, err := endpointbootstrap.New(endpointbootstrap.Deps{
		DB:           s.DB(),
		Logger:       slog.Default(),
		EnrollSecret: testSecret,
	})
	require.NoError(t, err)
	require.NoError(t, endpointCtx.ApplySchema(t.Context()))

	ps := policy.New(s.DB())
	h := admin.New(endpointCtx.Service(), ps, s, nil /* catalog */, slog.Default())

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, endpointCtx, s
}

// enrollHost issues a real enrollment row through the endpoint Service
// so the policy fan-out tests have something to fan out to.
func enrollHost(t *testing.T, ctx context.Context, ep *endpointbootstrap.Endpoint, hostID string) {
	t.Helper()
	_, err := ep.Service().Enroll(ctx, endpointapi.EnrollRequest{
		EnrollSecret: testSecret,
		HardwareUUID: hostID,
		Hostname:     "h",
		OSVersion:    "o",
		AgentVersion: "v",
	}, "127.0.0.1")
	require.NoError(t, err)
}

func TestGetPolicy_SeedRow(t *testing.T) {
	srv, _, _ := newAdminServer(t)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/policy", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var got map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, "default", got["name"])
	assert.EqualValues(t, 1, got["version"])
}

func TestPutPolicy_HappyPath(t *testing.T) {
	srv, ep, s := newAdminServer(t)
	ctx := t.Context()

	// Enroll two hosts so there's something to fan out to.
	for _, hostID := range []string{testUUID, "12345678-1234-1234-1234-123456789012"} {
		enrollHost(t, ctx, ep, hostID)
	}

	// Phase 2 requires hashes to be 64-char lowercase hex (SHA-256). Use a fake digest of
	// the right shape -- the server just persists + fans out, no SHA validation runs.
	body, _ := json.Marshal(map[string]any{
		"paths":  []string{"/tmp/qa-block", "/opt/evil"},
		"hashes": []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		"actor":  "qa-tester",
		"reason": "phase-2 smoke",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, srv.URL+"/api/policy", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var got map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.EqualValues(t, 2, got["version"])

	// Every active host now has at least one set_blocklist command pending.
	// Two paths queued the command: the post-enroll fan-out (when PolicyProvider
	// is wired up here -- it isn't, so that goroutine is a no-op for this test)
	// and the explicit PUT fan-out we just exercised. Without the PolicyProvider
	// in this admin test, only the PUT fan-out runs, so we expect exactly 1.
	for _, hostID := range []string{testUUID, "12345678-1234-1234-1234-123456789012"} {
		cmds, err := s.ListCommands(ctx, hostID, "pending")
		require.NoError(t, err)
		var setBlocklist int
		for _, c := range cmds {
			if c.CommandType == "set_blocklist" {
				setBlocklist++
			}
		}
		assert.Equal(t, 1, setBlocklist, "host %s should have one set_blocklist from the PUT fan-out", hostID)
	}
}

func TestPutPolicy_MissingActor(t *testing.T) {
	srv, _, _ := newAdminServer(t)
	body, _ := json.Marshal(map[string]any{"paths": []string{"/tmp/x"}})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, srv.URL+"/api/policy", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestPutPolicy_EmptyBlocklistAccepted(t *testing.T) {
	// "Clear everything" must be a first-class operation -- no paths + no hashes is a valid
	// edit so operators have a fast panic-button.
	srv, _, _ := newAdminServer(t)
	body, _ := json.Marshal(map[string]any{"actor": "qa-tester", "reason": "clear"})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, srv.URL+"/api/policy", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestPutPolicy_InvalidBlocklistReturns400 locks in the Phase 2 validation surface: a
// non-absolute path or a malformed hash gets a 400 with a stable error code.
func TestPutPolicy_InvalidBlocklistReturns400(t *testing.T) {
	srv, _, _ := newAdminServer(t)
	body, _ := json.Marshal(map[string]any{
		"paths":  []string{"relative/path"},
		"actor":  "qa-tester",
		"reason": "phase-2 negative",
	})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, srv.URL+"/api/policy", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var got map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, "invalid_blocklist", got["error"])
}
