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
	"github.com/fleetdm/edr/server/store"
)

const testUUID = "93DFC6F5-763D-5075-B305-8AC145D12F96"

func newAdminServer(t *testing.T) (*httptest.Server, *enrollment.Store) {
	t.Helper()
	s := store.OpenTestStore(t)
	es := enrollment.NewStore(s.DB())

	mux := http.NewServeMux()
	h := New(es, slog.Default())
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, es
}

func TestList_ReturnsEnrollmentRows(t *testing.T) {
	srv, es := newAdminServer(t)
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
	srv, es := newAdminServer(t)
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
	srv, _ := newAdminServer(t)
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
	srv, es := newAdminServer(t)
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

func TestRevoke_IdempotentPreservesFirstActor(t *testing.T) {
	srv, es := newAdminServer(t)
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
