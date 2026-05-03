package mysql_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	"github.com/fleetdm/edr/server/detection/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

// newTestStore wraps testdb.Open with detection's ApplySchema +
// MigrateSchema and returns a fresh mysql.Store. Lives in
// package mysql_test so the testdb import (which transitively pulls
// in detection/bootstrap) doesn't create a cycle with the production
// detection/internal/mysql package.
//
// Accepts testing.TB so the same fixture works for benchmarks (see
// perf_test.go); *testing.T and *testing.B both satisfy the
// interface.
func newTestStore(t testing.TB) *mysql.Store {
	t.Helper()
	db := testdb.Open(t)
	ctx := t.Context()
	require.NoError(t, testkit.ApplySchema(ctx, db))
	require.NoError(t, testkit.MigrateSchema(ctx, db))
	s, err := mysql.New(db)
	require.NoError(t, err)
	return s
}

func TestNew_RejectsNilDB(t *testing.T) {
	_, err := mysql.New(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db handle")
}

func TestStore_DBAndClose(t *testing.T) {
	s := newTestStore(t)
	assert.NotNil(t, s.DB(), "DB() returns the underlying *sqlx.DB")
	require.NoError(t, s.Close(), "Close is a no-op (the db handle is shared with cmd/main)")
	require.NoError(t, s.PingContext(t.Context()), "Ping after no-op Close still works")
}

func TestStore_CountEventsAndUnprocessed(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	count, err := s.CountEvents(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count, "fresh DB has no events")

	events := []api.Event{
		{EventID: "ce-1", HostID: "h", TimestampNs: 1, EventType: "fork", Payload: json.RawMessage(`{}`)},
		{EventID: "ce-2", HostID: "h", TimestampNs: 2, EventType: "fork", Payload: json.RawMessage(`{}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))

	count, err = s.CountEvents(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)

	unproc, err := s.CountUnprocessed(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), unproc, "freshly inserted events are unprocessed")
}

func TestStore_InsertEventsAtPinsTimestamp(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	events := []api.Event{
		{EventID: "ia-1", HostID: "h", TimestampNs: 100, EventType: "fork", Payload: json.RawMessage(`{}`)},
	}
	require.NoError(t, s.InsertEventsAt(ctx, events, 9999))

	// The caller's slice is stamped in place when the row was actually
	// inserted (vs deduped via INSERT IGNORE).
	assert.Equal(t, int64(9999), events[0].IngestedAtNs,
		"InsertEventsAt must pin the deterministic ingest timestamp")
}

func TestStore_FetchUnprocessedAndUnclaim(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	events := []api.Event{
		{EventID: "fu-1", HostID: "h", TimestampNs: 1, EventType: "fork", Payload: json.RawMessage(`{}`)},
		{EventID: "fu-2", HostID: "h", TimestampNs: 2, EventType: "fork", Payload: json.RawMessage(`{}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))

	got, err := s.FetchUnprocessed(ctx, 10)
	require.NoError(t, err)
	require.Len(t, got, 2)
	ids := []string{got[0].EventID, got[1].EventID}

	// After Fetch the rows are in state 2 (claimed). UnclaimEvents
	// transitions them back to state 0 so a future cycle can retry.
	require.NoError(t, s.UnclaimEvents(ctx, ids))

	got2, err := s.FetchUnprocessed(ctx, 10)
	require.NoError(t, err)
	assert.Len(t, got2, 2, "unclaimed events must be reclaimable")
}

func TestStore_FetchUnprocessedRejectsZeroLimit(t *testing.T) {
	s := newTestStore(t)
	out, err := s.FetchUnprocessed(t.Context(), 0)
	require.NoError(t, err)
	assert.Nil(t, out, "zero limit yields nil without a query")
}

func TestStore_MarkProcessedNoOpOnEmpty(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.MarkProcessed(t.Context(), nil))
	require.NoError(t, s.UnclaimEvents(t.Context(), nil))
}

func TestStore_CountAlerts(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	count, err := s.CountAlerts(ctx, api.AlertFilter{})
	require.NoError(t, err)
	assert.Equal(t, int64(0), count, "fresh DB has no alerts")

	// Seed a process row first (alerts.process_id has an FK to processes.id).
	_, err = s.InsertProcess(ctx, api.Process{
		HostID: "h", PID: 1, PPID: 0, Path: "/bin/test", ForkTimeNs: 1,
	})
	require.NoError(t, err)

	_, _, err = s.InsertAlert(ctx, api.Alert{
		HostID:      "h",
		RuleID:      "rule",
		Severity:    api.SeverityHigh,
		Title:       "T",
		Description: "D",
		ProcessID:   1,
	}, []string{})
	require.NoError(t, err)

	count, err = s.CountAlerts(ctx, api.AlertFilter{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	count, err = s.CountAlerts(ctx, api.AlertFilter{Severity: api.SeverityHigh})
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	count, err = s.CountAlerts(ctx, api.AlertFilter{HostID: "no-such"})
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)

	count, err = s.CountAlerts(ctx, api.AlertFilter{ProcessID: 1})
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestStore_GetChildProcessesFiltersByPPIDAndWindow(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	// Insert two children of pid 1 inside the window plus one outside.
	_, err := s.InsertProcess(ctx, api.Process{HostID: "h", PID: 10, PPID: 1, ForkTimeNs: 100})
	require.NoError(t, err)
	_, err = s.InsertProcess(ctx, api.Process{HostID: "h", PID: 11, PPID: 1, ForkTimeNs: 200})
	require.NoError(t, err)
	_, err = s.InsertProcess(ctx, api.Process{HostID: "h", PID: 12, PPID: 1, ForkTimeNs: 999})
	require.NoError(t, err)
	_, err = s.InsertProcess(ctx, api.Process{HostID: "h", PID: 20, PPID: 99, ForkTimeNs: 150})
	require.NoError(t, err)

	got, err := s.GetChildProcesses(ctx, "h", 1, api.TimeRange{FromNs: 0, ToNs: 500})
	require.NoError(t, err)
	require.Len(t, got, 2, "only 10 + 11 fall inside [0,500] with ppid=1")
	pids := []int{got[0].PID, got[1].PID}
	assert.ElementsMatch(t, []int{10, 11}, pids)
}

// Compile-time check that the package is wired correctly.
var _ context.Context = (context.Context)(nil)
