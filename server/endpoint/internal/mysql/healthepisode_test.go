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
	return selfHealEpisodeFor(hostID, component, "content_filter", openedAtNs)
}

// selfHealEpisodeFor names the provider as the episode's subject, and derives a distinct source event per provider, which is how two
// providers under one extension arrive: as two events, and so as two outages.
func selfHealEpisodeFor(hostID, component, provider string, openedAtNs int64) api.HealthEpisode {
	return selfHealEpisodeOf(hostID, component, provider, "evt-"+component+"-"+provider, openedAtNs)
}

// selfHealEpisodeOf names the source event too, which IS the episode's identity: two calls with one event id are one occurrence
// however else they differ.
func selfHealEpisodeOf(hostID, component, provider, eventID string, openedAtNs int64) api.HealthEpisode {
	detail, err := json.Marshal(api.SelfHealFailedDetail{Provider: provider, Outcome: "enable_ineffective", Attempts: 5})
	if err != nil {
		panic(err)
	}
	return api.HealthEpisode{
		HostID:        hostID,
		Component:     component,
		Subject:       provider,
		SourceEventID: eventID,
		Kind:          api.KindSelfHealFailed,
		Severity:      "critical",
		Title:         "EDR sensor could not be restored",
		Description:   "automatic recovery gave up on content_filter",
		Detail:        detail,
		OpenedAtNs:    openedAtNs,
	}
}

// openEpisodes returns hostID's currently open episodes, read back through SQL so the tests assert what is STORED rather than what
// a read method chose to return. There is no read API yet (it ships with the operator surface), and a test that could only see the
// write path's own return value would not notice a row written wrong.
func openEpisodes(t *testing.T, db *sqlx.DB, hostID string) []api.HealthEpisode {
	t.Helper()
	var out []api.HealthEpisode
	require.NoError(t, db.SelectContext(t.Context(), &out, `
		SELECT id, host_id, component, subject, kind, source_event_id, severity, title, description, detail, opened_at_ns, resolved_at_ns
		FROM host_health_episodes WHERE host_id = ? AND resolved_at_ns IS NULL ORDER BY id`, hostID))
	return out
}

func allEpisodes(t *testing.T, db *sqlx.DB, hostID string) []api.HealthEpisode {
	t.Helper()
	var out []api.HealthEpisode
	require.NoError(t, db.SelectContext(t.Context(), &out, `
		SELECT id, host_id, component, subject, kind, source_event_id, severity, title, description, detail, opened_at_ns, resolved_at_ns
		FROM host_health_episodes WHERE host_id = ? ORDER BY id`, hostID))
	return out
}

// spec:server-host-status/the-server-records-host-health-episodes/a-fault-that-needs-a-person-opens-an-episode
//
// recov is the recovered-component set a status snapshot reports, written as "this component was observed healthy at this instant".
func recov(components ...api.RecoveredComponent) []api.RecoveredComponent { return components }

// rc names one recovered component and when it was observed healthy on the host.
func rc(compType string, atNs int64) api.RecoveredComponent {
	return api.RecoveredComponent{Type: compType, AtNs: atNs}
}

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

// spec:server-host-status/the-server-records-host-health-episodes/a-redelivered-report-does-not-open-a-second-episode
//
// TestOpenHealthEpisode_ARedeliveredEventDoesNotOpenASecond is the property the identity exists for. The agent emits one event per
// outage, so the repetition the server sees is REDELIVERY: event delivery is at-least-once, so a batch can be evaluated, acked
// poorly, and evaluated again. Each replay must collapse onto the episode already recorded.
//
// A replay must also not MOVE the opened_at time: the episode's value is when the outage began, and re-stamping it would leave a
// week-long outage permanently reporting that it started a minute ago.
func TestOpenHealthEpisode_ARedeliveredEventDoesNotOpenASecond(t *testing.T) {
	t.Parallel()
	s, db := newTestStoreWithDB(t)

	opened, err := s.OpenHealthEpisode(t.Context(), selfHealEpisodeOf("host-a", "network_extension", "content_filter", "evt-1", 100))
	require.NoError(t, err)
	require.True(t, opened)

	// A plain loop rather than subtests: each redelivery is asserted against the store the previous one left behind, so the steps are
	// sequential by nature and cannot be parallel subtests (tparallel), and serial subtests would name steps without isolating them.
	for _, atNs := range []int64{200, 300, 400} {
		opened, err = s.OpenHealthEpisode(t.Context(),
			selfHealEpisodeOf("host-a", "network_extension", "content_filter", "evt-1", atNs))
		require.NoError(t, err)
		assert.False(t, opened, "a redelivered event is the same occurrence and is already recorded (delivery at %d)", atNs)
	}

	got := openEpisodes(t, db, "host-a")
	require.Len(t, got, 1, "one outage is one episode however many times its event is delivered")
	assert.Equal(t, int64(100), got[0].OpenedAtNs, "the episode keeps the instant the outage began, not the latest delivery")
}

// TestOpenHealthEpisode_ARedeliveryAfterTheEpisodeClosedIsStillTheSameOccurrence is the case an open-episode key could not hold, and
// the reason the identity is the occurrence rather than "is something open for this component".
//
// The sequence is ordinary under at-least-once delivery: the event is evaluated and opens an episode, a check-in closes it, and then
// the batch is redelivered after a nack or a lost ack. Keyed on openness, the closed row would no longer match and the replay would
// record the same outage a second time, which is exactly what the requirement forbids.
func TestOpenHealthEpisode_ARedeliveryAfterTheEpisodeClosedIsStillTheSameOccurrence(t *testing.T) {
	t.Parallel()
	s, db := newTestStoreWithDB(t)

	e := selfHealEpisodeOf("host-a", "network_extension", "content_filter", "evt-1", 100)
	opened, err := s.OpenHealthEpisode(t.Context(), e)
	require.NoError(t, err)
	require.True(t, opened)

	require.NoError(t, s.UpsertHostHealth(t.Context(), "host-a", "healthy", nil, 900))
	closed, err := s.CloseHealthEpisodes(t.Context(), "host-a", recov(rc("network_extension", 900)), 900)
	require.NoError(t, err)
	require.Equal(t, int64(1), closed)

	opened, err = s.OpenHealthEpisode(t.Context(), e)
	require.NoError(t, err)
	assert.False(t, opened, "the outage is already recorded; a replay must not resurrect it as a second one")
	assert.Len(t, allEpisodes(t, db, "host-a"), 1)
	assert.Empty(t, openEpisodes(t, db, "host-a"), "and must not reopen a host that has recovered")
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

	closed, err := s.CloseHealthEpisodes(t.Context(), "host-a", recov(rc("network_extension", 900)), 900)
	require.NoError(t, err)
	assert.Equal(t, int64(1), closed)
	assert.Empty(t, openEpisodes(t, db, "host-a"), "a component reporting healthy ends its outage")

	all := allEpisodes(t, db, "host-a")
	require.Len(t, all, 1)
	require.NotNil(t, all[0].ResolvedAtNs)
	assert.Equal(t, int64(900), *all[0].ResolvedAtNs)
	assert.Equal(t, int64(800), *all[0].ResolvedAtNs-all[0].OpenedAtNs, "the interval is the answer the record exists to give")

	// A second outage on the same component later is a separate episode, not a reopening of the first. It is a separate OCCURRENCE,
	// carrying its own event, which is exactly how the agent reports it: the event fires at the edge where a repair budget is spent,
	// so a later exhaustion is a later event.
	opened, err := s.OpenHealthEpisode(t.Context(),
		selfHealEpisodeOf("host-a", "network_extension", "content_filter", "evt-second-outage", 1000))
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

	closed, err := s.CloseHealthEpisodes(t.Context(), "host-a", recov(rc("network_extension", 900)), 900)
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

	closed, err := s.CloseHealthEpisodes(t.Context(), "host-a",
		recov(rc("network_extension", 900), rc("endpoint_security_extension", 900)), 900)
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

	closed, err := s.CloseHealthEpisodes(t.Context(), "host-a", recov(rc("network_extension", 900)), 900)
	require.NoError(t, err)
	assert.Equal(t, int64(1), closed)
	assert.Empty(t, openEpisodes(t, db, "host-a"))
	assert.Len(t, openEpisodes(t, db, "host-b"), 1, "one host recovering says nothing about another")
}

// spec:server-host-status/the-server-records-host-health-episodes/two-parts-of-one-component-failing-are-two-episodes
//
// TestOpenHealthEpisode_TwoProvidersUnderOneComponentAreTwoEpisodes: one extension owns both capture providers and the self-heal
// controller reports each independently, as two events. An identity too coarse to tell them apart (a key on the component alone, as
// an earlier cut had) would let the second provider's failure collide with the first and be discarded, taking its provider, outcome
// and attempt count with it, and the host would read as having one provider down while two were.
func TestOpenHealthEpisode_TwoProvidersUnderOneComponentAreTwoEpisodes(t *testing.T) {
	t.Parallel()
	s, db := newTestStoreWithDB(t)

	for _, provider := range []string{"content_filter", "dns_proxy"} {
		opened, err := s.OpenHealthEpisode(t.Context(), selfHealEpisodeFor("host-a", "network_extension", provider, 100))
		require.NoError(t, err)
		assert.True(t, opened, "each provider's failure is its own outage")
	}

	got := openEpisodes(t, db, "host-a")
	require.Len(t, got, 2)
	var subjects []string
	for _, e := range got {
		subjects = append(subjects, e.Subject)
	}
	assert.ElementsMatch(t, []string{"content_filter", "dns_proxy"}, subjects)

	// Redelivering one of them still does not open a third: the occurrence is the identity, so a repeat of one event is not an outage.
	opened, err := s.OpenHealthEpisode(t.Context(), selfHealEpisodeFor("host-a", "network_extension", "dns_proxy", 200))
	require.NoError(t, err)
	assert.False(t, opened, "the same provider's event redelivered is the same occurrence")
	assert.Len(t, openEpisodes(t, db, "host-a"), 2)
}

// spec:server-host-status/the-server-records-host-health-episodes/an-episode-closes-when-the-component-recovers
//
// TestCloseHealthEpisodes_ComponentRecoveryClosesEveryProviderUnderIt: an operator restores the COMPONENT (they re-activate the
// extension), not one provider inside it, so its recovery ends every fault reported under it. Closing only the matching subject
// would leave the other provider's episode open forever on a host that is fine.
func TestCloseHealthEpisodes_ComponentRecoveryClosesEveryProviderUnderIt(t *testing.T) {
	t.Parallel()
	s, db := newTestStoreWithDB(t)

	for _, provider := range []string{"content_filter", "dns_proxy"} {
		_, err := s.OpenHealthEpisode(t.Context(), selfHealEpisodeFor("host-a", "network_extension", provider, 100))
		require.NoError(t, err)
	}
	closed, err := s.CloseHealthEpisodes(t.Context(), "host-a", recov(rc("network_extension", 900)), 900)
	require.NoError(t, err)
	assert.Equal(t, int64(2), closed)
	assert.Empty(t, openEpisodes(t, db, "host-a"))
}

// TestCloseHealthEpisodes_StampsTheComponentsOwnTransitionInstant: the interval is the record's whole value, so both ends come from
// the agent's clock. The end is when the component was observed healthy ON THE HOST, not when its check-in reached us, which would
// pad every outage by the delivery delay.
func TestCloseHealthEpisodes_StampsTheComponentsOwnTransitionInstant(t *testing.T) {
	t.Parallel()
	s, db := newTestStoreWithDB(t)

	_, err := s.OpenHealthEpisode(t.Context(), selfHealEpisode("host-a", "network_extension", 100))
	require.NoError(t, err)

	// The component recovered at 500; the snapshot carrying that news arrived at 900.
	closed, err := s.CloseHealthEpisodes(t.Context(), "host-a", recov(rc("network_extension", 500)), 900)
	require.NoError(t, err)
	require.Equal(t, int64(1), closed)

	all := allEpisodes(t, db, "host-a")
	require.Len(t, all, 1)
	require.NotNil(t, all[0].ResolvedAtNs)
	assert.Equal(t, int64(500), *all[0].ResolvedAtNs, "the outage ended when the host says it ended, not when we heard about it")
}

// TestCloseHealthEpisodes_ARecoveryThatPredatesTheFaultDoesNotCloseIt covers the case the close exists to get right and an earlier
// cut got wrong. A healthy snapshot taken BEFORE the fault can arrive after the fault event, delayed in transit, and still be the
// newest health row, so the ordering guard alone lets it through. Its component's healthy transition predates the opening, which
// means it describes the component before it failed, not a recovery from that failure.
//
// Stamping GREATEST(opened, transition) instead turned this into a zero-length outage and closed a fault that was still in progress:
// the host this record exists to surface would read as fixed. The same rule is what stops a skewed host from recording an episode
// that ends before it began, because such a resolution never satisfies it.
func TestCloseHealthEpisodes_ARecoveryThatPredatesTheFaultDoesNotCloseIt(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		transitionNs int64
		wantClosed   bool
	}{
		{"a transition before the fault opened is the pre-fault state", 400, false},
		{"a transition at the instant the fault opened is a recovery", 1_000, true},
		{"a transition after the fault opened is a recovery", 1_500, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, db := newTestStoreWithDB(t)
			_, err := s.OpenHealthEpisode(t.Context(), selfHealEpisode("host-a", "network_extension", 1_000))
			require.NoError(t, err)

			_, err = s.CloseHealthEpisodes(t.Context(), "host-a", recov(rc("network_extension", tc.transitionNs)), 2_000)
			require.NoError(t, err)

			all := allEpisodes(t, db, "host-a")
			require.Len(t, all, 1)
			if !tc.wantClosed {
				assert.Nil(t, all[0].ResolvedAtNs, "a reading of the component before it failed says nothing about whether it recovered")
				return
			}
			require.NotNil(t, all[0].ResolvedAtNs)
			assert.Equal(t, tc.transitionNs, *all[0].ResolvedAtNs)
			assert.GreaterOrEqual(t, *all[0].ResolvedAtNs, all[0].OpenedAtNs, "an episode may be instantaneous but never negative")
		})
	}
}

// TestCloseHealthEpisodes_IgnoresASnapshotThatLostTheOrderingRace: host_health is last-writer-wins on reported_at_ns, so a delayed
// snapshot that arrives after a newer one did NOT update the stored component states. Acting on it here would resolve an episode
// from a reading the current health row has already rejected, leaving the host recorded as recovered while it reports unhealthy.
func TestCloseHealthEpisodes_IgnoresASnapshotThatLostTheOrderingRace(t *testing.T) {
	t.Parallel()
	s, db := newTestStoreWithDB(t)

	_, err := s.OpenHealthEpisode(t.Context(), selfHealEpisode("host-a", "network_extension", 100))
	require.NoError(t, err)
	// The current health row was written by a NEWER snapshot than the delayed one below.
	require.NoError(t, s.UpsertHostHealth(t.Context(), "host-a", "unhealthy", nil, 5_000))

	closed, err := s.CloseHealthEpisodes(t.Context(), "host-a", recov(rc("network_extension", 900)), 900)
	require.NoError(t, err)
	assert.Zero(t, closed, "a snapshot too old to update current health is too old to resolve an outage")
	assert.Len(t, openEpisodes(t, db, "host-a"), 1)

	// The same report arriving as the newest one does close it.
	require.NoError(t, s.UpsertHostHealth(t.Context(), "host-a", "healthy", nil, 9_000))
	closed, err = s.CloseHealthEpisodes(t.Context(), "host-a", recov(rc("network_extension", 9_000)), 9_000)
	require.NoError(t, err)
	assert.Equal(t, int64(1), closed)
}

// spec:server-host-status/the-server-records-host-health-episodes/a-fault-whose-component-cannot-be-named-is-still-recorded
//
// TestOpenHealthEpisode_AFaultWithNoComponentIsRecordedAndStaysOpen: an agent too old to report which component owns the failed
// provider still names a host that is not capturing, which is what an operator has to act on, so the report is recorded rather than
// dropped. It simply has nothing to close it: no component recovery can be matched to an episode that names no component, and
// inventing one to make the row resolvable would manufacture the recovery the record exists to report honestly.
func TestOpenHealthEpisode_AFaultWithNoComponentIsRecordedAndStaysOpen(t *testing.T) {
	t.Parallel()
	s, db := newTestStoreWithDB(t)

	e := selfHealEpisode("host-a", "", 100)
	opened, err := s.OpenHealthEpisode(t.Context(), e)
	require.NoError(t, err)
	require.True(t, opened, "a report that names a host with no capture is worth recording even unattributed")

	// Every component this host has recovers; the unattributed episode is not among them.
	closed, err := s.CloseHealthEpisodes(t.Context(), "host-a",
		recov(rc("network_extension", 900), rc("endpoint_security_extension", 900)), 900)
	require.NoError(t, err)
	assert.Zero(t, closed)
	require.Len(t, openEpisodes(t, db, "host-a"), 1, "nothing can close an episode that names no component")
}
