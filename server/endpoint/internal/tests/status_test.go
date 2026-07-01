//go:build integration

// Per-context integration tests for the agent-health check-in (POST /api/status, issue #359). Exercise the full stack:
// HostToken middleware -> status handler -> api.Service.RecordStatus -> host_health upsert, against a real MySQL.

package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/endpoint/bootstrap"
)

// statusFixture enrolls a host over the real service and stands up the check-in endpoint behind the host-token middleware, exactly as
// cmd/main mounts it. Returns the server, the host token, and the host_id so a test can POST snapshots and read host_health back.
func statusFixture(t *testing.T, uuid string) (*bootstrap.Endpoint, *sqlx.DB, *httptest.Server, string) {
	t.Helper()
	ep, db := newEndpointWithDB(t)
	res, err := ep.Service().Enroll(t.Context(), api.EnrollRequest{
		EnrollSecret: testEnrollSecret,
		HardwareUUID: uuid,
		Hostname:     "h",
		OSVersion:    "macOS 26",
		AgentVersion: "0.4.0",
	}, "192.0.2.10")
	require.NoError(t, err)
	srv := httptest.NewServer(ep.HostTokenMiddleware()(ep.StatusHandler()))
	t.Cleanup(srv.Close)
	return ep, db, srv, res.HostToken
}

func postStatus(t *testing.T, srv *httptest.Server, token, body string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/status", strings.NewReader(body))
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	return resp.StatusCode
}

type healthRow struct {
	OverallStatus string `db:"overall_status"`
	Components    []byte `db:"components"`
	ReportedAtNs  int64  `db:"reported_at_ns"`
}

func readHealth(t *testing.T, db *sqlx.DB, hostID string) (healthRow, bool) {
	t.Helper()
	var row healthRow
	err := db.GetContext(t.Context(), &row,
		`SELECT overall_status, components, reported_at_ns FROM host_health WHERE host_id = ?`, hostID)
	if err != nil {
		return healthRow{}, false
	}
	return row, true
}

// spec:server-host-status/the-server-accepts-and-persists-a-host-status-snapshot/a-valid-snapshot-is-stored-as-the-latest-health-for-the-host
func TestRecordStatus_HTTP_PersistsAndRollsUp(t *testing.T) {
	t.Parallel()
	uuid := "11111111-1111-1111-1111-111111111111"
	_, db, srv, token := statusFixture(t, uuid)

	body := `{"agent_version":"0.4.0","reported_at_ns":100,"components":[
		{"type":"endpoint_security_extension","status":"unhealthy","reason":"never_connected","last_transition_ns":90},
		{"type":"network_extension","status":"healthy","reason":"activated","last_transition_ns":80}
	]}`
	require.Equal(t, http.StatusNoContent, postStatus(t, srv, token, body))

	row, ok := readHealth(t, db, uuid)
	require.True(t, ok)
	assert.Equal(t, string(api.HealthUnhealthy), row.OverallStatus)
	assert.EqualValues(t, 100, row.ReportedAtNs)
	assert.Contains(t, string(row.Components), "endpoint_security_extension")
	assert.Contains(t, string(row.Components), "never_connected")
}

// spec:server-host-status/the-server-accepts-and-persists-a-host-status-snapshot/a-later-snapshot-replaces-an-earlier-one
func TestRecordStatus_HTTP_LastWriterWins(t *testing.T) {
	t.Parallel()
	uuid := "22222222-2222-2222-2222-222222222222"
	_, db, srv, token := statusFixture(t, uuid)

	healthy := `{"agent_version":"0.4.0","reported_at_ns":%d,"components":[{"type":"network_extension","status":"healthy","last_transition_ns":1}]}`
	unhealthy := `{"agent_version":"0.4.0","reported_at_ns":%d,"components":[{"type":"network_extension","status":"unhealthy","last_transition_ns":1}]}`

	require.Equal(t, http.StatusNoContent, postStatus(t, srv, token, fmt.Sprintf(healthy, 100)))
	require.Equal(t, http.StatusNoContent, postStatus(t, srv, token, fmt.Sprintf(unhealthy, 200)))

	row, ok := readHealth(t, db, uuid)
	require.True(t, ok)
	assert.Equal(t, string(api.HealthUnhealthy), row.OverallStatus)
	assert.EqualValues(t, 200, row.ReportedAtNs)

	// A stale (older reported_at_ns) post must not clobber the fresher snapshot.
	require.Equal(t, http.StatusNoContent, postStatus(t, srv, token, fmt.Sprintf(healthy, 50)))
	row, ok = readHealth(t, db, uuid)
	require.True(t, ok)
	assert.Equal(t, string(api.HealthUnhealthy), row.OverallStatus, "a stale post must not overwrite a fresher snapshot")
	assert.EqualValues(t, 200, row.ReportedAtNs)
}

// spec:server-host-status/the-server-accepts-and-persists-a-host-status-snapshot/an-unknown-component-type-is-stored-verbatim
func TestRecordStatus_HTTP_UnknownTypeStored(t *testing.T) {
	t.Parallel()
	uuid := "33333333-3333-3333-3333-333333333333"
	_, db, srv, token := statusFixture(t, uuid)

	body := `{"agent_version":"0.4.0","reported_at_ns":5,"components":[{"type":"future_signal","status":"healthy","reason":"brand_new","last_transition_ns":1}]}`
	require.Equal(t, http.StatusNoContent, postStatus(t, srv, token, body))

	row, ok := readHealth(t, db, uuid)
	require.True(t, ok)
	assert.Equal(t, string(api.HealthHealthy), row.OverallStatus)
	assert.Contains(t, string(row.Components), "future_signal")
	assert.Contains(t, string(row.Components), "brand_new")
}

// spec:server-host-status/the-server-accepts-and-persists-a-host-status-snapshot/an-invalid-status-value-is-rejected
func TestRecordStatus_HTTP_InvalidStatusRejected(t *testing.T) {
	t.Parallel()
	uuid := "44444444-4444-4444-4444-444444444444"
	_, db, srv, token := statusFixture(t, uuid)

	body := `{"agent_version":"0.4.0","reported_at_ns":5,"components":[{"type":"network_extension","status":"borked","last_transition_ns":1}]}`
	require.Equal(t, http.StatusBadRequest, postStatus(t, srv, token, body))

	_, ok := readHealth(t, db, uuid)
	assert.False(t, ok, "a rejected snapshot must store nothing")
}

// spec:server-host-status/the-server-accepts-and-persists-a-host-status-snapshot/an-unauthenticated-check-in-is-rejected
func TestRecordStatus_HTTP_Unauthenticated(t *testing.T) {
	t.Parallel()
	uuid := "55555555-5555-5555-5555-555555555555"
	_, db, srv, _ := statusFixture(t, uuid)

	body := `{"agent_version":"0.4.0","reported_at_ns":5,"components":[{"type":"network_extension","status":"healthy","last_transition_ns":1}]}`
	assert.Equal(t, http.StatusUnauthorized, postStatus(t, srv, "", body))

	_, ok := readHealth(t, db, uuid)
	assert.False(t, ok, "an unauthenticated check-in must store nothing")
}
