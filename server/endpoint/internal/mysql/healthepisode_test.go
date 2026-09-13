package mysql_test

import (
	"encoding/json"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/endpoint/api"
)

func selfHealEpisode(hostID, component string, openedAtNs int64) api.HealthEpisode {
	detail, err := json.Marshal(api.SelfHealFailedDetail{Provider: "content_filter", Outcome: "enable_ineffective", Attempts: 5})
	if err != nil {
		panic(err)
	}
	return api.HealthEpisode{
		HostID:      hostID,
		Component:   component,
		Kind:        api.KindSelfHealFailed,
		Severity:    "critical",
		Title:       "EDR sensor could not be restored",
		Description: "automatic recovery gave up on content_filter",
		Detail:      detail,
		OpenedAtNs:  openedAtNs,
	}
}

// openEpisodes returns hostID's currently open episodes, read back through SQL so the tests assert what is STORED rather than what
// a read method chose to return. There is no read API yet (it ships with the operator surface), and a test that could only see the
// write path's own return value would not notice a row written wrong.
func openEpisodes(t *testing.T, db *sqlx.DB, hostID string) []api.HealthEpisode {
	t.Helper()
	var out []api.HealthEpisode
	require.NoError(t, db.SelectContext(t.Context(), &out, `
		SELECT id, host_id, component, kind, severity, title, description, detail, opened_at_ns, resolved_at_ns
		FROM host_health_episodes WHERE host_id = ? AND resolved_at_ns IS NULL ORDER BY id`, hostID))
	return out
}

func allEpisodes(t *testing.T, db *sqlx.DB, hostID string) []api.HealthEpisode {
	t.Helper()
	var out []api.HealthEpisode
	require.NoError(t, db.SelectContext(t.Context(), &out, `
		SELECT id, host_id, component, kind, severity, title, description, detail, opened_at_ns, resolved_at_ns
		FROM host_health_episodes WHERE host_id = ? ORDER BY id`, hostID))
	return out
}

// spec:server-host-status/the-server-records-host-health-episodes/a-fault-that-needs-a-person-opens-an-episode
//
// TestOpenHealthEpisode_RecordsTheFaultsOwnFields: the point of an episode over the level state that reports the same fault is that
// it keeps the machine-readable detail, so an operational surface can filter and group on the provider and the outcome instead of
// reading a sentence.
func TestOpenHealthEpisode_RecordsTheFaultsOwnFields(t *testing.T) {
	t.Parallel()
	s, db := newTestStoreWithDB(t)

	opened, err := s.OpenHealthEpisode(t.Context(), selfHealEpisode("host-a", "network_extension", 100))
	require.NoError(t, err)
	assert.True(t, opened, "the first report of a fault is what opens its episode")

	got := openEpisodes(t, db, "host-a")
	require.Len(t, got, 1)
	assert.Equal(t, "network_extension", got[0].Component)
	assert.Equal(t, api.KindSelfHealFailed, got[0].Kind)
	assert.Equal(t, "critical", got[0].Severity)
	assert.Equal(t, int64(100), got[0].OpenedAtNs)
	assert.True(t, got[0].Open(), "a fault nobody has fixed yet is an open episode")

	var detail api.SelfHealFailedDetail
	require.NoError(t, json.Unmarshal(got[0].Detail, &detail))
	assert.Equal(t, api.SelfHealFailedDetail{Provider: "content_filter", Outcome: "enable_ineffective", Attempts: 5}, detail)
}

// spec:server-host-status/the-server-records-host-health-episodes/a-re-asserted-fault-does-not-open-a-second-episode
//
// TestOpenHealthEpisode_ReAssertingAFaultDoesNotOpenASecond is the property the whole schema shape exists for. The fault is level
// state on the agent and is re-reported for as long as it lasts, so a recorder that opened a row per report would describe one
// outage as hundreds and make the duration meaningless.
//
// The later report also must not MOVE the opened_at time: the episode's value is when the outage began, and re-stamping it on every
// report would leave a week-long outage permanently reporting that it started a minute ago.
func TestOpenHealthEpisode_ReAssertingAFaultDoesNotOpenASecond(t *testing.T) {
	t.Parallel()
	s, db := newTestStoreWithDB(t)

	opened, err := s.OpenHealthEpisode(t.Context(), selfHealEpisode("host-a", "network_extension", 100))
	require.NoError(t, err)
	require.True(t, opened)

	for _, at := range []int64{200, 300, 400} {
		opened, err = s.OpenHealthEpisode(t.Context(), selfHealEpisode("host-a", "network_extension", at))
		require.NoError(t, err)
		assert.False(t, opened, "a fault that already has an open episode is not opened again")
	}

	got := openEpisodes(t, db, "host-a")
	require.Len(t, got, 1, "one outage is one episode however many times it is reported")
	assert.Equal(t, int64(100), got[0].OpenedAtNs, "the episode keeps the instant the outage began, not the latest report")
}

// TestOpenHealthEpisode_SeparatesHostsComponentsAndKinds: the uniqueness is per (host, component, kind), so two hosts with the same
// fault, or one host with a fault on two components, are separate outages and must each get their own episode. A key that was too
// broad would silently merge them and under-report the fleet.
func TestOpenHealthEpisode_SeparatesHostsComponentsAndKinds(t *testing.T) {
	t.Parallel()
	s, db := newTestStoreWithDB(t)

	for _, e := range []api.HealthEpisode{
		selfHealEpisode("host-a", "network_extension", 100),
		selfHealEpisode("host-b", "network_extension", 100),
		selfHealEpisode("host-a", "endpoint_security_extension", 100),
	} {
		opened, err := s.OpenHealthEpisode(t.Context(), e)
		require.NoError(t, err)
		assert.True(t, opened)
	}

	assert.Len(t, openEpisodes(t, db, "host-a"), 2, "two components in fault on one host are two outages")
	assert.Len(t, openEpisodes(t, db, "host-b"), 1)
}

// spec:server-host-status/the-server-records-host-health-episodes/an-episode-closes-when-the-component-recovers
//
// TestCloseHealthEpisodes_ClosesOnRecoveryAndAllowsTheNextOne covers the lifecycle the record exists to capture: an outage ends
// when the component reports healthy, and a LATER outage on the same component is its own episode rather than being swallowed by
// the closed one.
func TestCloseHealthEpisodes_ClosesOnRecoveryAndAllowsTheNextOne(t *testing.T) {
	t.Parallel()
	s, db := newTestStoreWithDB(t)

	_, err := s.OpenHealthEpisode(t.Context(), selfHealEpisode("host-a", "network_extension", 100))
	require.NoError(t, err)

	closed, err := s.CloseHealthEpisodes(t.Context(), "host-a", []string{"network_extension"}, 900)
	require.NoError(t, err)
	assert.Equal(t, int64(1), closed)
	assert.Empty(t, openEpisodes(t, db, "host-a"), "a component reporting healthy ends its outage")

	all := allEpisodes(t, db, "host-a")
	require.Len(t, all, 1)
	require.NotNil(t, all[0].ResolvedAtNs)
	assert.Equal(t, int64(900), *all[0].ResolvedAtNs)
	assert.Equal(t, int64(800), *all[0].ResolvedAtNs-all[0].OpenedAtNs, "the interval is the answer the record exists to give")

	// A second outage on the same component later is a separate episode, not a reopening of the first.
	opened, err := s.OpenHealthEpisode(t.Context(), selfHealEpisode("host-a", "network_extension", 1000))
	require.NoError(t, err)
	assert.True(t, opened)
	assert.Len(t, allEpisodes(t, db, "host-a"), 2, "two outages separated by a recovery are two records")
}

// TestCloseHealthEpisodes_OnlyClosesTheComponentsReportedHealthy is the honesty property. An episode is closed only by a component
// that actually said it recovered: closing on anything else would stamp an end time nobody observed, which is the one number the
// record exists to provide.
func TestCloseHealthEpisodes_OnlyClosesTheComponentsReportedHealthy(t *testing.T) {
	t.Parallel()
	s, db := newTestStoreWithDB(t)

	for _, c := range []string{"network_extension", "endpoint_security_extension"} {
		_, err := s.OpenHealthEpisode(t.Context(), selfHealEpisode("host-a", c, 100))
		require.NoError(t, err)
	}

	closed, err := s.CloseHealthEpisodes(t.Context(), "host-a", []string{"network_extension"}, 900)
	require.NoError(t, err)
	assert.Equal(t, int64(1), closed)

	still := openEpisodes(t, db, "host-a")
	require.Len(t, still, 1)
	assert.Equal(t, "endpoint_security_extension", still[0].Component,
		"a component that did not report healthy keeps its episode open, because nobody told us that fault ended")
}

// spec:server-host-status/the-server-records-host-health-episodes/recovery-with-no-open-episode-is-not-an-error
//
// TestCloseHealthEpisodes_HealthyWithNothingOpenIsNotAnError: the overwhelmingly common check-in is a healthy host with no episode
// to close, and it must be a cheap no-op rather than an error path.
func TestCloseHealthEpisodes_HealthyWithNothingOpenIsNotAnError(t *testing.T) {
	t.Parallel()
	s, db := newTestStoreWithDB(t)

	closed, err := s.CloseHealthEpisodes(t.Context(), "host-a", []string{"network_extension", "endpoint_security_extension"}, 900)
	require.NoError(t, err)
	assert.Zero(t, closed)

	// And an empty recovered set closes nothing at all rather than everything, which is the dangerous reading of "no components
	// named": a host reporting no healthy components has not recovered from anything.
	_, err = s.OpenHealthEpisode(t.Context(), selfHealEpisode("host-a", "network_extension", 100))
	require.NoError(t, err)
	closed, err = s.CloseHealthEpisodes(t.Context(), "host-a", nil, 900)
	require.NoError(t, err)
	assert.Zero(t, closed)
	assert.Len(t, openEpisodes(t, db, "host-a"), 1, "an empty healthy set must not be read as 'everything recovered'")
}

// TestCloseHealthEpisodes_DoesNotReachOtherHosts: the close is driven by one host's check-in, so it must be scoped to that host.
// An unscoped UPDATE would resolve the whole fleet's outages the first time any host reported healthy.
func TestCloseHealthEpisodes_DoesNotReachOtherHosts(t *testing.T) {
	t.Parallel()
	s, db := newTestStoreWithDB(t)

	for _, h := range []string{"host-a", "host-b"} {
		_, err := s.OpenHealthEpisode(t.Context(), selfHealEpisode(h, "network_extension", 100))
		require.NoError(t, err)
	}

	closed, err := s.CloseHealthEpisodes(t.Context(), "host-a", []string{"network_extension"}, 900)
	require.NoError(t, err)
	assert.Equal(t, int64(1), closed)
	assert.Empty(t, openEpisodes(t, db, "host-a"))
	assert.Len(t, openEpisodes(t, db, "host-b"), 1, "one host recovering says nothing about another")
}
