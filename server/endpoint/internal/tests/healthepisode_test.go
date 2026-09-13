//go:build integration

// Per-context integration tests for host health episodes (issue #778). Exercise the half the store tests cannot: that a real
// agent check-in, arriving through the host-token middleware and the status handler, is what closes an episode.

package tests

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/endpoint/bootstrap"
)

// openSelfHealEpisode records a capture-provider repair failure for hostID through the same recorder the detection engine holds, so
// the test starts from the state the engine actually produces rather than from a hand-written row.
func openSelfHealEpisode(t *testing.T, ep *bootstrap.Endpoint, hostID, component string) {
	t.Helper()
	detail, err := json.Marshal(api.SelfHealFailedDetail{Provider: "content_filter", Outcome: "enable_failed", Attempts: 3})
	require.NoError(t, err)
	opened, err := ep.HealthEpisodeRecorder().OpenHealthEpisode(t.Context(), api.HealthEpisode{
		HostID:      hostID,
		Component:   component,
		Kind:        api.KindSelfHealFailed,
		Severity:    "critical",
		Title:       "EDR sensor could not be restored",
		Description: "automatic recovery gave up on content_filter",
		Detail:      detail,
		OpenedAtNs:  1_000,
	})
	require.NoError(t, err)
	require.True(t, opened)
}

func openEpisodeCount(t *testing.T, db *sqlx.DB, hostID string) int {
	t.Helper()
	var n int
	require.NoError(t, db.GetContext(t.Context(), &n,
		`SELECT COUNT(*) FROM host_health_episodes WHERE host_id = ? AND resolved_at_ns IS NULL`, hostID))
	return n
}

func resolvedAt(t *testing.T, db *sqlx.DB, hostID, component string) *int64 {
	t.Helper()
	var out *int64
	require.NoError(t, db.GetContext(t.Context(), &out,
		`SELECT resolved_at_ns FROM host_health_episodes WHERE host_id = ? AND component = ? ORDER BY id DESC LIMIT 1`,
		hostID, component))
	return out
}

// hostIDFor resolves the enrolled host's id, since the episode rows are keyed by it rather than by the hardware UUID the fixture
// enrolls with.
func hostIDFor(t *testing.T, db *sqlx.DB, uuid string) string {
	t.Helper()
	var id string
	require.NoError(t, db.GetContext(t.Context(), &id, `SELECT host_id FROM enrollments WHERE host_id = ?`, uuid))
	return id
}

// spec:server-host-status/the-server-records-host-health-episodes/an-episode-closes-when-the-component-recovers
//
// TestStatusCheckIn_ClosesTheEpisodeOfARecoveredComponent is the lifecycle end to end. The store tests prove the close works; this
// proves the check-in is wired to perform it, which is the part that silently would not happen if the call were dropped.
func TestStatusCheckIn_ClosesTheEpisodeOfARecoveredComponent(t *testing.T) {
	t.Parallel()
	const uuid = "A1B2C3D4-0000-4000-8000-000000000101"
	ep, db, srv, token := statusFixture(t, uuid)
	hostID := hostIDFor(t, db, uuid)

	openSelfHealEpisode(t, ep, hostID, "network_extension")
	require.Equal(t, 1, openEpisodeCount(t, db, hostID))

	body := fmt.Sprintf(`{"agent_version":"0.4.0","reported_at_ns":%d,"components":[
		{"type":"network_extension","status":"healthy","last_transition_ns":%d}
	]}`, 5_000, 5_000)
	require.Equal(t, 204, postStatus(t, srv, token, body))

	assert.Zero(t, openEpisodeCount(t, db, hostID), "the component reporting healthy ends its outage")
	got := resolvedAt(t, db, hostID, "network_extension")
	require.NotNil(t, got)
	assert.Equal(t, int64(5_000), *got, "the end is stamped from the snapshot that observed it, not from the server's clock")
}

// TestStatusCheckIn_LeavesAnUnrecoveredComponentOpen: a check-in that reports the component still unhealthy is not a recovery, and
// neither is one that has stopped mentioning the component at all. Closing on either would stamp an end time nobody observed, which
// is the single number the record exists to provide.
func TestStatusCheckIn_LeavesAnUnrecoveredComponentOpen(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		components string
	}{
		{
			name:       "the component is still unhealthy",
			components: `{"type":"network_extension","status":"unhealthy","reason":"self_heal_failed","last_transition_ns":5000}`,
		},
		{
			// A degraded component is working but not fully, which is not the fault being over.
			name:       "the component is degraded",
			components: `{"type":"network_extension","status":"degraded","last_transition_ns":5000}`,
		},
		{
			// Unknown means no state is known. An absence of information is not evidence of recovery.
			name:       "the component reports unknown",
			components: `{"type":"network_extension","status":"unknown","last_transition_ns":5000}`,
		},
		{
			// The agent has stopped reporting the component entirely. It has not told us the fault ended.
			name:       "the component is no longer reported at all",
			components: `{"type":"endpoint_security_extension","status":"healthy","last_transition_ns":5000}`,
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			uuid := fmt.Sprintf("A1B2C3D4-0000-4000-8000-00000000020%d", i)
			ep, db, srv, token := statusFixture(t, uuid)
			hostID := hostIDFor(t, db, uuid)

			openSelfHealEpisode(t, ep, hostID, "network_extension")
			body := fmt.Sprintf(`{"agent_version":"0.4.0","reported_at_ns":5000,"components":[%s]}`, tc.components)
			require.Equal(t, 204, postStatus(t, srv, token, body))

			assert.Equal(t, 1, openEpisodeCount(t, db, hostID), "only an explicit healthy report ends the outage")
		})
	}
}

// spec:server-host-status/the-server-records-host-health-episodes/recovery-with-no-open-episode-is-not-an-error
//
// TestStatusCheckIn_HealthyHostWithNoEpisodeIsUnaffected: the ordinary check-in, which is nearly all of them. It must pass through
// the new close step without error and without inventing a record.
func TestStatusCheckIn_HealthyHostWithNoEpisodeIsUnaffected(t *testing.T) {
	t.Parallel()
	const uuid = "A1B2C3D4-0000-4000-8000-000000000301"
	_, db, srv, token := statusFixture(t, uuid)
	hostID := hostIDFor(t, db, uuid)

	body := `{"agent_version":"0.4.0","reported_at_ns":5000,"components":[
		{"type":"network_extension","status":"healthy","last_transition_ns":5000},
		{"type":"endpoint_security_extension","status":"healthy","last_transition_ns":5000}
	]}`
	require.Equal(t, 204, postStatus(t, srv, token, body))
	assert.Zero(t, openEpisodeCount(t, db, hostID))

	var total int
	require.NoError(t, db.GetContext(t.Context(), &total, `SELECT COUNT(*) FROM host_health_episodes WHERE host_id = ?`, hostID))
	assert.Zero(t, total, "a healthy check-in records no episode of its own")
}
