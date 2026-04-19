package admin

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/enrollment"
	"github.com/fleetdm/edr/server/policy"
	"github.com/fleetdm/edr/server/store"
)

const testUUID = "93DFC6F5-763D-5075-B305-8AC145D12F96"

func newAdminServer(t *testing.T) (*httptest.Server, *enrollment.Store, *store.Store) {
	t.Helper()
	s := store.OpenTestStore(t)
	es := enrollment.NewStore(s.DB())
	ps := policy.New(s.DB())

	mux := http.NewServeMux()
	h := New(es, ps, s, slog.Default())
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, es, s
}

func TestList_ReturnsEnrollmentRows(t *testing.T) {
	srv, es, _ := newAdminServer(t)
	_, err := es.Register(t.Context(), enrollment.RegisterRequest{
		HostID: testUUID, Hostname: "h", AgentVersion: "v", OSVersion: "o", SourceIP: "127.0.0.1",
	})
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/admin/enrollments", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var got []map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	require.Len(t, got, 1)
	assert.Equal(t, testUUID, got[0]["host_id"])
	assert.NotContains(t, got[0], "host_token")
	assert.NotContains(t, got[0], "host_token_hash")
}

func TestRevoke_HappyPath(t *testing.T) {
	srv, es, _ := newAdminServer(t)
	reg, err := es.Register(t.Context(), enrollment.RegisterRequest{
		HostID: testUUID, Hostname: "h", AgentVersion: "v", OSVersion: "o", SourceIP: "127.0.0.1",
	})
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]string{
		"reason": "compromised",
		"actor":  "jane@customer.com",
	})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		srv.URL+"/api/v1/admin/enrollments/"+testUUID+"/revoke", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	// The previously-issued token no longer verifies.
	_, err = es.Verify(t.Context(), reg.HostToken)
	assert.ErrorIs(t, err, enrollment.ErrTokenMismatch)
}

func TestRevoke_NotFound(t *testing.T) {
	srv, _, _ := newAdminServer(t)
	body, _ := json.Marshal(map[string]string{"reason": "x", "actor": "y"})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		srv.URL+"/api/v1/admin/enrollments/AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA/revoke",
		bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestRevoke_MissingBody(t *testing.T) {
	srv, es, _ := newAdminServer(t)
	_, err := es.Register(t.Context(), enrollment.RegisterRequest{
		HostID: testUUID, Hostname: "h", AgentVersion: "v", OSVersion: "o", SourceIP: "127.0.0.1",
	})
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]string{"reason": ""})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		srv.URL+"/api/v1/admin/enrollments/"+testUUID+"/revoke", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestGetPolicy_SeedRow(t *testing.T) {
	srv, _, _ := newAdminServer(t)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/admin/policy", nil)
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
	srv, es, s := newAdminServer(t)

	// Enroll two hosts so there's something to fan out to.
	for _, hostID := range []string{testUUID, "12345678-1234-1234-1234-123456789012"} {
		_, err := es.Register(t.Context(), enrollment.RegisterRequest{
			HostID: hostID, Hostname: "h", AgentVersion: "v", OSVersion: "o", SourceIP: "127.0.0.1",
		})
		require.NoError(t, err)
	}

	// Phase 2 requires hashes to be 64-char lowercase hex (SHA-256). Use a fake digest of
	// the right shape — the server just persists + fans out, no SHA validation runs.
	body, _ := json.Marshal(map[string]any{
		"paths":  []string{"/tmp/qa-block", "/opt/evil"},
		"hashes": []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		"actor":  "qa-tester",
		"reason": "phase-2 smoke",
	})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, srv.URL+"/api/v1/admin/policy", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var got map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.EqualValues(t, 2, got["version"])

	// Every active host now has exactly one pending set_blocklist command — the one this
	// PUT fanned out. (Register was called directly, bypassing the enrollment Handler that
	// would have queued its own initial command; the first-enroll path is covered in
	// TestHandler_EnrollQueuesInitialPolicy in server/enrollment.)
	for _, hostID := range []string{testUUID, "12345678-1234-1234-1234-123456789012"} {
		cmds, err := s.ListCommands(t.Context(), hostID, "pending")
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
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, srv.URL+"/api/v1/admin/policy", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestPutPolicy_EmptyBlocklistAccepted(t *testing.T) {
	// "Clear everything" must be a first-class operation — no paths + no hashes is a valid
	// edit so operators have a fast panic-button.
	srv, _, _ := newAdminServer(t)
	body, _ := json.Marshal(map[string]any{"actor": "qa-tester", "reason": "clear"})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, srv.URL+"/api/v1/admin/policy", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestPutPolicy_InvalidBlocklistReturns400 locks in the Phase 2 validation surface: a
// non-absolute path or a malformed hash gets a 400 with a stable error code, not the old
// 500 that made it look like a server bug.
func TestPutPolicy_InvalidBlocklistReturns400(t *testing.T) {
	srv, _, _ := newAdminServer(t)
	body, _ := json.Marshal(map[string]any{
		"paths":  []string{"relative/path"},
		"actor":  "qa-tester",
		"reason": "phase-2 negative",
	})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, srv.URL+"/api/v1/admin/policy", bytes.NewReader(body))
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

func TestRevoke_IdempotentPreservesFirstActor(t *testing.T) {
	srv, es, _ := newAdminServer(t)
	_, err := es.Register(t.Context(), enrollment.RegisterRequest{
		HostID: testUUID, Hostname: "h", AgentVersion: "v", OSVersion: "o", SourceIP: "127.0.0.1",
	})
	require.NoError(t, err)

	revoke := func(actor, reason string) int {
		body, _ := json.Marshal(map[string]string{"reason": reason, "actor": actor})
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
			srv.URL+"/api/v1/admin/enrollments/"+testUUID+"/revoke", bytes.NewReader(body))
		require.NoError(t, err)
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		return resp.StatusCode
	}
	assert.Equal(t, http.StatusNoContent, revoke("first", "compromised"))
	assert.Equal(t, http.StatusNoContent, revoke("second", "different"))

	got, err := es.Get(t.Context(), testUUID)
	require.NoError(t, err)
	require.NotNil(t, got.RevokedBy)
	assert.Equal(t, "first", *got.RevokedBy)
	require.NotNil(t, got.RevokeReason)
	assert.Equal(t, "compromised", *got.RevokeReason)
}
