//go:build integration

// Integration coverage for the recorded sensor faults the host-health read reports (issue #778), against real MySQL with both the
// detection and endpoint schemas applied: episodes are read alongside the health snapshot, open ones first, bounded, and present
// even for a host that has never posted a snapshot.

package tests

import (
	"context"
	"fmt"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/bootstrap"
)

// insertEpisode writes an episode row the way the endpoint context's recorder would. Written with SQL rather than through that
// context because this is detection's read of a shared table, and a test that went through the writer would couple the two contexts
// the production read deliberately does not.
func insertEpisode(t *testing.T, db *sqlx.DB, hostID, subject, eventID string, openedAtNs int64, resolvedAtNs *int64) {
	t.Helper()
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO host_health_episodes
			(host_id, component, subject, kind, source_event_id, severity, title, description, detail, opened_at_ns, resolved_at_ns)
		VALUES (?, 'network_extension', ?, 'self_heal_failed', ?, 'critical', 'EDR sensor could not be restored', NULL, ?, ?, ?)`,
		hostID, subject, eventID, fmt.Sprintf(`{"provider":%q,"outcome":"enable_failed","attempts":3}`, subject), openedAtNs, resolvedAtNs)
	require.NoError(t, err)
}

// spec:server-host-status/the-host-api-surfaces-per-host-health/the-detail-reports-recorded-sensor-faults
//
// TestHostHealth_ReportsEpisodesOpenFirst: a host's recorded faults ride the same read the host page already makes, open ones first
// and newest first, then resolved ones newest first. Open first because an open fault is a host that needs someone now, and a list
// ordered purely by time would bury yesterday's still-open fault beneath this morning's resolved blip. The test's timestamps are
// chosen so that pure time order would put a resolved episode first, which is what makes the ordering assertion able to fail.
func TestHostHealth_ReportsEpisodesOpenFirst(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	db := d.Store().DB()
	const host = "EPISODE-HOST-0001"

	_, err := db.ExecContext(t.Context(), `INSERT INTO host_health (host_id, overall_status, components, reported_at_ns)
		VALUES (?, 'unhealthy', NULL, 100)`, host)
	require.NoError(t, err)

	insertEpisode(t, db, host, "content_filter", "evt-old-open", 1_000, nil)          // oldest, still open
	insertEpisode(t, db, host, "dns_proxy", "evt-resolved", 5_000, new(int64(6_000))) // newest overall, resolved
	insertEpisode(t, db, host, "content_filter", "evt-new-open", 3_000, nil)          // open
	insertEpisode(t, db, "OTHER-HOST", "content_filter", "evt-elsewhere", 9_000, nil) // another host's

	h, err := d.Store().HostHealth(t.Context(), host)
	require.NoError(t, err)

	require.Len(t, h.Episodes, 3, "another host's episode must not appear")
	got := make([]string, 0, len(h.Episodes))
	for _, e := range h.Episodes {
		got = append(got, fmt.Sprintf("%d:%v", e.OpenedAtNs, e.ResolvedAtNs != nil))
	}
	assert.Equal(t, []string{"3000:false", "1000:false", "5000:true"}, got,
		"open episodes newest first, then resolved, even though the resolved one is the newest overall")

	first := h.Episodes[0]
	assert.Equal(t, "content_filter", first.Subject)
	assert.Equal(t, "self_heal_failed", first.Kind)
	assert.Equal(t, "critical", first.Severity)
	assert.Empty(t, first.Description, "a NULL description reads as empty rather than failing the scan")
	assert.JSONEq(t, `{"provider":"content_filter","outcome":"enable_failed","attempts":3}`, string(first.Detail))

	assert.Equal(t, "unhealthy", h.OverallStatus, "the rollup is the snapshot's; episodes are reported beside it, not folded into it")
}

// spec:server-host-status/the-host-api-surfaces-per-host-health/a-host-with-no-snapshot-still-reports-its-recorded-faults
//
// TestHostHealth_ReportsEpisodesWithoutASnapshot: episodes are written from the event stream and snapshots from the status check-in,
// independently. A host can have a recorded fault and no snapshot, and returning early on the missing snapshot would hide exactly the
// record the operator opened the page to find.
func TestHostHealth_ReportsEpisodesWithoutASnapshot(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	const host = "EPISODE-HOST-0002"
	insertEpisode(t, d.Store().DB(), host, "content_filter", "evt-1", 1_000, nil)

	h, err := d.Store().HostHealth(t.Context(), host)
	require.NoError(t, err)
	assert.Equal(t, api.HostHealthUnknown, h.OverallStatus)
	require.Len(t, h.Episodes, 1, "a recorded fault must be reported even when the host has never posted a snapshot")
}

// TestHostHealth_EpisodesAreAnEmptyListNotNull: a host with no recorded faults gets [] on the wire, so a client iterates it without a
// guard. The UI reads `episodes.length` directly; a null here would throw on every clean host's page.
func TestHostHealth_EpisodesAreAnEmptyListNotNull(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})

	for _, host := range []string{"EPISODE-HOST-NO-SNAPSHOT", "EPISODE-HOST-WITH-SNAPSHOT"} {
		if host == "EPISODE-HOST-WITH-SNAPSHOT" {
			_, err := d.Store().DB().ExecContext(t.Context(), `INSERT INTO host_health (host_id, overall_status, components, reported_at_ns)
				VALUES (?, 'healthy', NULL, 100)`, host)
			require.NoError(t, err)
		}
		h, err := d.Store().HostHealth(t.Context(), host)
		require.NoError(t, err)
		require.NotNil(t, h.Episodes, "%s: episodes must be an empty list, not nil", host)
		assert.Empty(t, h.Episodes)
	}
}

// TestHostHealth_BoundsEachHalfOfTheEpisodeRead: both halves are bounded, and the open half needs it as much as the resolved one. An
// episode recorded by an agent too old to name its component can never close, so a host that failed repeatedly on such an agent holds
// one open episode per outage indefinitely. The resolved episodes kept are the most recent.
func TestHostHealth_BoundsEachHalfOfTheEpisodeRead(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	db := d.Store().DB()
	const host = "EPISODE-HOST-0003"
	const perHalf = 25 // above the read limit on both halves
	for i := range perHalf {
		insertEpisode(t, db, host, "content_filter", fmt.Sprintf("open-%d", i), int64(1_000+i), nil)
		insertEpisode(t, db, host, "dns_proxy", fmt.Sprintf("resolved-%d", i), int64(1_000+i), new(int64(10_000+i)))
	}

	h, err := d.Store().HostHealth(t.Context(), host)
	require.NoError(t, err)

	var open, resolved []api.HostHealthEpisode
	for _, e := range h.Episodes {
		if e.ResolvedAtNs == nil {
			open = append(open, e)
		} else {
			resolved = append(resolved, e)
		}
	}
	assert.Len(t, open, 20, "open episodes are bounded too, because some can never close")
	require.Len(t, resolved, 20)
	assert.Equal(t, int64(10_000+perHalf-1), *resolved[0].ResolvedAtNs, "the resolved episodes kept are the most recently resolved")
}
