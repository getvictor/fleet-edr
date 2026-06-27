package mysql_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	"github.com/fleetdm/edr/server/detection/testkit"
	"github.com/fleetdm/edr/server/testdb"
	"github.com/fleetdm/edr/server/testdb/full"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
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
	s, _ := newTestStoreWithArchive(tb)
	return s
}

// newTestStoreWithArchive is newTestStore plus the in-memory EventArchive the store reads correlation + evidence from, returned so tests
// that need a populated archive (alert evidence, network correlation) can seed it with archive.Insert. The store and the returned
// archive share the same instance, so seeding the archive is visible to the store's reads.
func newTestStoreWithArchive(tb testing.TB) (*mysql.Store, visibilityapi.EventArchive) {
	tb.Helper()
	db := testdb.Open(tb)
	ctx := tb.Context()
	require.NoError(tb, testkit.ApplySchema(ctx, db))
	archive := testkit.NewMemArchive()
	s, err := mysql.New(db, archive)
	require.NoError(tb, err)
	return s, archive
}

// newFullSchemaStore is newTestStore's cross-context sibling for the handful of store tests that exercise ListHosts, which LEFT JOINs
// the endpoint context's enrollments table. The detection-only schema newTestStore applies lacks that table, so those tests open a
// full-schema fixture (every bounded context's DDL) via testdb/full instead. testdb/full is the sanctioned cross-context schema surface
// (arch-go allows **.testdb here); it takes *testing.T, so this helper is test-only (no benchmark variant needed).
func newFullSchemaStore(t *testing.T) *mysql.Store {
	t.Helper()
	s, err := mysql.New(full.Open(t), testkit.NewMemArchive())
	require.NoError(t, err)
	return s
}

func TestNew_RejectsNilDB(t *testing.T) {
	t.Parallel()
	_, err := mysql.New(nil, testkit.NewMemArchive())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db handle")
}

func TestNew_RejectsNilArchive(t *testing.T) {
	t.Parallel()
	_, err := mysql.New(testdb.Open(t), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "event archive")
}

func TestStore_DBAndClose(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	assert.NotNil(t, s.DB(), "DB() returns the underlying *sqlx.DB")
	require.NoError(t, s.Close(), "Close is a no-op (the db handle is shared with cmd/main)")
	require.NoError(t, s.PingContext(t.Context()), "Ping after no-op Close still works")
}

func TestStore_CountAlerts(t *testing.T) {
	t.Parallel()
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

// spec:server-detection-rules-engine/persisted-alert-schema/an-alert-with-no-attributable-process-omits-the-process-link
// spec:server-detection-rules-engine/alert-dedup-by-subject/process-less-findings-dedup-on-a-rule-supplied-subject
// TestStore_InsertAlert_ProcessLess covers the ADR-0008-amendment persistence path: a process-less alert (ProcessID 0, a rule-supplied
// Subject) persists with a NULL process_id (no fk_alerts_process violation) and dedups on subject rather than process_id. The same
// daemon registration dedups; a different one produces a second alert; the row reads back with ProcessID 0 via the read-path COALESCE.
func TestStore_InsertAlert_ProcessLess(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := t.Context()

	mk := func(subject string) (int64, bool) {
		id, created, err := s.InsertAlert(ctx, api.Alert{
			HostID:      "h",
			RuleID:      "privilege_launchd_plist_write",
			Severity:    api.SeverityHigh,
			Title:       "LaunchDaemon persistence",
			Description: "D",
			ProcessID:   0, // process-less: no live attacker process (the BTM instigator is Apple's smd)
			Subject:     subject,
		}, []string{})
		require.NoError(t, err, "process-less insert must not trip fk_alerts_process")
		return id, created
	}

	id1, created1 := mk("launchdaemon:/Library/LaunchDaemons/com.a.plist")
	require.True(t, created1)

	id1Again, created1Again := mk("launchdaemon:/Library/LaunchDaemons/com.a.plist")
	assert.False(t, created1Again, "same subject dedups")
	assert.Equal(t, id1, id1Again, "dedup returns the existing alert id")

	_, created2 := mk("launchdaemon:/Library/LaunchDaemons/com.b.plist")
	assert.True(t, created2, "a different daemon (subject) is a distinct alert")

	count, err := s.CountAlerts(ctx, api.AlertFilter{})
	require.NoError(t, err)
	assert.Equal(t, int64(2), count, "two distinct subjects -> two alerts; the duplicate subject deduped")

	got, err := s.GetAlert(ctx, id1)
	require.NoError(t, err)
	assert.Equal(t, int64(0), got.ProcessID, "process-less alert reads back ProcessID 0 (NULL coalesced)")

	// A process-less alert that forgets its Subject is a programming error: defaulting to "0" would collapse every such
	// alert for the same (source, host, rule) into one row. InsertAlert rejects it rather than mis-deduplicating.
	_, _, errNoSubject := s.InsertAlert(ctx, api.Alert{
		HostID: "h", RuleID: "privilege_launchd_plist_write", Severity: api.SeverityHigh,
		Title: "T", Description: "D", ProcessID: 0, Subject: "",
	}, []string{})
	require.Error(t, errNoSubject, "process-less alert with empty Subject must be rejected, not deduped to '0'")
}

func TestStore_GetChildProcessesFiltersByPPIDAndWindow(t *testing.T) {
	t.Parallel()
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

// spec:server-process-graph-builder/ttl-reconciliation-respects-snapshot-freshness/snapshot-row-with-fresh-heartbeats-survives-ttl
func TestStore_ReconcileStaleProcesses_LeavesFreshSnapshotRow(t *testing.T) {
	t.Parallel()
	// Issue #173: a snapshot row whose last_seen_ns is inside the TTL window must NOT be reconciled. The reconciler's predicate uses
	// COALESCE(last_seen_ns, fork_time_ns) so fresh heartbeats keep the row alive even when fork_time_ns is ancient.
	s := newTestStore(t)
	ctx := t.Context()

	const tenHours int64 = 10 * 3600 * 1_000_000_000
	const sixHours int64 = 6 * 3600 * 1_000_000_000
	const fiveMinutes int64 = 5 * 60 * 1_000_000_000

	now := int64(1_000_000_000_000_000) // fixed nanosecond clock so the math is auditable
	oldFork := now - tenHours           // forked 10h ago: would normally be reconciled
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

// spec:server-process-graph-builder/ttl-reconciliation-respects-snapshot-freshness/snapshot-row-without-recent-heartbeats-is-closed
func TestStore_ReconcileStaleProcesses_ClosesStaleSnapshotRow(t *testing.T) {
	t.Parallel()
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
	// also uses COALESCE: keeps the UI's "exited at" timestamp meaningful for snapshot rows whose fork_time is the
	// extension-startup moment.
	assert.Equal(t, staleLastSeen+sixHours, *got.ExitTimeNs)
}

// spec:server-process-graph-builder/ttl-reconciliation-respects-snapshot-freshness/non-snapshot-row-with-missing-exit-is-closed-issue-6-regression-guard
func TestStore_ReconcileStaleProcesses_ClosesStaleLiveRow_NoRegression(t *testing.T) {
	t.Parallel()
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
		// LastSeenNs stays nil: live rows never bump this column.
	})
	require.NoError(t, err)

	reconciled, err := s.ReconcileStaleProcesses(ctx, now-sixHours, sixHours)
	require.NoError(t, err)
	assert.Equal(t, int64(1), reconciled, "live row with no last_seen falls back to fork_time, gets reconciled")
}

// Compile-time check that the package is wired correctly.
var _ context.Context = (context.Context)(nil)
