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

// newTestStore wraps testdb.Open with detection's ApplySchema and
// returns a fresh mysql.Store. Lives in package mysql_test so the
// testdb import (which transitively pulls in detection/bootstrap)
// doesn't create a cycle with the production detection/internal/mysql
// package.
//
// Accepts testing.TB so the same fixture works for benchmarks (see
// perf_test.go); *testing.T and *testing.B both satisfy the
// interface.
func newTestStore(tb testing.TB) *mysql.Store {
	tb.Helper()
	db := testdb.Open(tb)
	ctx := tb.Context()
	require.NoError(tb, testkit.ApplySchema(ctx, db))
	s, err := mysql.New(db)
	require.NoError(tb, err)
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

func TestStore_ReconcileStaleProcesses_LeavesFreshSnapshotRow(t *testing.T) {
	// Issue #173: a snapshot row whose last_seen_ns is inside the TTL window must NOT be reconciled. The reconciler's predicate uses
	// COALESCE(last_seen_ns, fork_time_ns) so fresh heartbeats keep the row alive even when fork_time_ns is ancient.
	s := newTestStore(t)
	ctx := t.Context()

	const tenHours int64 = 10 * 3600 * 1_000_000_000
	const sixHours int64 = 6 * 3600 * 1_000_000_000
	const fiveMinutes int64 = 5 * 60 * 1_000_000_000

	now := int64(1_000_000_000_000_000) // fixed nanosecond clock so the math is auditable
	oldFork := now - tenHours           // forked 10h ago — would normally be reconciled
	freshLastSeen := now - fiveMinutes  // heartbeated 5min ago

	_, err := s.InsertProcess(ctx, api.Process{
		HostID: "h-fresh", PID: 1, PPID: 0, Path: "/sbin/launchd",
		ForkTimeNs: oldFork, ExecTimeNs: &oldFork,
		IsSnapshot: true, LastSeenNs: &freshLastSeen,
	})
	require.NoError(t, err)

	reconciled, err := s.ReconcileStaleProcesses(ctx, now-sixHours, sixHours)
	require.NoError(t, err)
	assert.Equal(t, int64(0), reconciled, "fresh snapshot row must not be force-exited")

	got, err := s.GetProcessByPID(ctx, "h-fresh", 1, now+1)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Nil(t, got.ExitTimeNs, "row must still be alive")
}

func TestStore_ReconcileStaleProcesses_ClosesStaleSnapshotRow(t *testing.T) {
	// Issue #173 negative: a snapshot row with no recent heartbeats (last_seen_ns older than TTL) IS reconciled. Confirms the
	// predicate doesn't accidentally exempt every snapshot row forever.
	s := newTestStore(t)
	ctx := t.Context()

	const tenHours int64 = 10 * 3600 * 1_000_000_000
	const sixHours int64 = 6 * 3600 * 1_000_000_000
	const sevenHours int64 = 7 * 3600 * 1_000_000_000

	now := int64(1_000_000_000_000_000)
	oldFork := now - tenHours
	staleLastSeen := now - sevenHours // last heartbeat was 7h ago; TTL is 6h → stale

	_, err := s.InsertProcess(ctx, api.Process{
		HostID: "h-stale", PID: 2, PPID: 0, Path: "/sbin/zombie",
		ForkTimeNs: oldFork, ExecTimeNs: &oldFork,
		IsSnapshot: true, LastSeenNs: &staleLastSeen,
	})
	require.NoError(t, err)

	reconciled, err := s.ReconcileStaleProcesses(ctx, now-sixHours, sixHours)
	require.NoError(t, err)
	assert.Equal(t, int64(1), reconciled, "snapshot row with last_seen older than TTL must be force-exited")

	// Query at staleLastSeen so GetProcessByPID's "alive at atTimeNs" predicate matches the row (fork_time_ns <= atTimeNs &&
	// exit_time_ns >= atTimeNs). The synthesised exit is at staleLastSeen + maxAge, comfortably > atTimeNs.
	got, err := s.GetProcessByPID(ctx, "h-stale", 2, staleLastSeen)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.NotNil(t, got.ExitTimeNs)
	assert.NotNil(t, got.ExitReason)
	assert.Equal(t, api.ExitReasonTTLReconciliation, *got.ExitReason)
	// Synthesised exit lands at last_seen_ns + maxAge (not fork_time_ns + maxAge) because the reconciler's exit_time_ns expression
	// also uses COALESCE - keeps the UI's "exited at" timestamp meaningful for snapshot rows whose fork_time is the
	// extension-startup moment.
	assert.Equal(t, staleLastSeen+sixHours, *got.ExitTimeNs)
}

func TestStore_ReconcileStaleProcesses_ClosesStaleLiveRow_NoRegression(t *testing.T) {
	// Issue #6 regression guard: a non-snapshot row with an ancient fork_time_ns and last_seen_ns IS NULL is still subject to TTL
	// reconciliation. The COALESCE predicate degenerates to fork_time_ns for these rows, preserving the original #6 behaviour.
	s := newTestStore(t)
	ctx := t.Context()

	const tenHours int64 = 10 * 3600 * 1_000_000_000
	const sixHours int64 = 6 * 3600 * 1_000_000_000

	now := int64(1_000_000_000_000_000)
	oldFork := now - tenHours

	_, err := s.InsertProcess(ctx, api.Process{
		HostID: "h-live-stale", PID: 3, PPID: 0, Path: "/bin/forgotten",
		ForkTimeNs: oldFork, ExecTimeNs: &oldFork,
		IsSnapshot: false,
		// LastSeenNs: nil — live rows never bump this column.
	})
	require.NoError(t, err)

	reconciled, err := s.ReconcileStaleProcesses(ctx, now-sixHours, sixHours)
	require.NoError(t, err)
	assert.Equal(t, int64(1), reconciled, "live row with no last_seen falls back to fork_time, gets reconciled")
}

// Compile-time check that the package is wired correctly.
var _ context.Context = (context.Context)(nil)
