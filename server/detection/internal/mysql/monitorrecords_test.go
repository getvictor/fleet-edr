package mysql_test

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	"github.com/fleetdm/edr/server/detection/testkit"
	"github.com/fleetdm/edr/server/testdb"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// monitorRecord is a process-less monitor record whose title repeats its dedup subject, so a test can find it in a listing.
func monitorRecord(subject string, eventIDs ...string) mysql.MonitorRecord {
	return mysql.MonitorRecord{
		Alert: api.Alert{
			HostID: "h1", RuleID: "watching", Severity: api.SeverityLow, Title: subject, Description: "d", Subject: subject,
			Techniques: api.JSONStringSlice{"T1059"},
		},
		EventIDs: eventIDs,
	}
}

func monitorRecordsByTitle(t *testing.T, s *mysql.Store) map[string]api.Alert {
	t.Helper()
	records, err := s.ListAlerts(t.Context(), api.AlertFilter{HostID: "h1", Disposition: api.AlertDispositionMonitor, Limit: 1000})
	require.NoError(t, err)
	byTitle := make(map[string]api.Alert, len(records))
	for _, r := range records {
		byTitle[r.Title] = r
	}
	return byTitle
}

// spec:server-detection-rules-engine/monitor-records-are-written-per-batch/a-batch-s-monitor-records-are-written-together
//
// A batch's monitor records carry what one InsertAlert per record wrote: the row as a monitor record, its event links, and the
// evidence the archive holds for them, including an event two records share.
func TestInsertMonitorRecords_KeepsEachRecordWithItsLinksAndEvidence(t *testing.T) {
	t.Parallel()
	s, archive := newTestStoreWithArchive(t)
	ctx := t.Context()
	require.NoError(t, archive.Insert(ctx, []api.Event{
		{EventID: "shared", HostID: "h1", TimestampNs: 100, EventType: "exec", Payload: json.RawMessage(`{"pid":1}`)},
		{EventID: "own", HostID: "h1", TimestampNs: 200, EventType: "exec", Payload: json.RawMessage(`{"pid":2}`)},
	}))

	require.NoError(t, s.InsertMonitorRecords(ctx, []mysql.MonitorRecord{
		monitorRecord("test:first", "shared", "own", "shared"),
		monitorRecord("test:second", "shared", "aged-out"),
	}))

	records := monitorRecordsByTitle(t, s)
	require.Len(t, records, 2)
	first, second := records["test:first"], records["test:second"]
	assert.Equal(t, api.AlertDispositionMonitor, first.Disposition, "kept as a monitor record whatever the caller set")
	assert.Equal(t, api.AlertSourceDetection, first.Source)
	links, err := s.GetAlertEventIDs(ctx, first.ID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"shared", "own"}, links, "duplicates collapse")
	links, err = s.GetAlertEventIDs(ctx, second.ID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"shared", "aged-out"}, links, "an event the archive no longer holds is still linked")
	evidence, err := s.GetAlertEventPayloads(ctx, first.ID)
	require.NoError(t, err)
	assert.Len(t, evidence, 2)
	evidence, err = s.GetAlertEventPayloads(ctx, second.ID)
	require.NoError(t, err)
	require.Len(t, evidence, 1, "the shared event's evidence is copied to each record, and the aged-out one has none")
	assert.Equal(t, "shared", evidence[0].EventID)
}

// A retried batch writes its records again, and the dedup key makes that a no-op for the rows while adding any newly linked event.
func TestInsertMonitorRecords_ARetryDeduplicates(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := t.Context()
	require.NoError(t, s.InsertMonitorRecords(ctx, []mysql.MonitorRecord{monitorRecord("test:again", "e1")}))
	require.NoError(t, s.InsertMonitorRecords(ctx, []mysql.MonitorRecord{
		monitorRecord("test:again", "e1", "e2"), monitorRecord("test:new", "e3"),
	}))

	records := monitorRecordsByTitle(t, s)
	require.Len(t, records, 2)
	links, err := s.GetAlertEventIDs(ctx, records["test:again"].ID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"e1", "e2"}, links)
}

// recordingArchive records the size of each archive read, so a test can see how a batch's reads are bounded.
type recordingArchive struct {
	visibilityapi.EventArchive
	readSizes []int
}

func (a *recordingArchive) EventsByIDs(ctx context.Context, eventIDs []string) ([]api.Event, error) {
	a.readSizes = append(a.readSizes, len(eventIDs))
	return a.EventArchive.EventsByIDs(ctx, eventIDs)
}

// More records than one chunk takes are all written, and the archive is read once per chunk of records, for only that chunk's
// events, so a batch with many findings neither sends one unbounded query nor holds every record's evidence at once.
func TestInsertMonitorRecords_ReadsAndWritesInBoundedChunks(t *testing.T) {
	t.Parallel()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	archive := &recordingArchive{EventArchive: testkit.NewMemArchive()}
	s, err := mysql.New(db, archive, nil)
	require.NoError(t, err)
	const n = 250
	records := make([]mysql.MonitorRecord, n)
	for i := range records {
		records[i] = monitorRecord("test:many-"+strconv.Itoa(i), "e-"+strconv.Itoa(i), "shared")
	}

	require.NoError(t, s.InsertMonitorRecords(t.Context(), records))
	assert.Len(t, monitorRecordsByTitle(t, s), n)
	assert.Equal(t, []int{101, 101, 51}, archive.readSizes, "one read per 100 records, of that chunk's distinct events")
}

// A record that cannot be deduplicated is refused before anything is written, as InsertAlert refuses it.
func TestInsertMonitorRecords_RefusesARecordWithoutADedupSubject(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	err := s.InsertMonitorRecords(t.Context(), []mysql.MonitorRecord{
		monitorRecord("test:fine", "e1"),
		{Alert: api.Alert{HostID: "h1", RuleID: "watching", Severity: api.SeverityLow, Title: "t"}},
	})
	require.ErrorContains(t, err, "process-less alert requires a non-empty Subject")
	assert.Empty(t, monitorRecordsByTitle(t, s))
}
