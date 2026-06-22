package mysql_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	"github.com/fleetdm/edr/server/detection/testkit"
	"github.com/fleetdm/edr/server/testdb"
	"github.com/fleetdm/edr/server/testdb/full"
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

// newFullSchemaStore is newTestStore's cross-context sibling for the handful of store tests that exercise ListHosts, which LEFT JOINs
// the endpoint context's enrollments table. The detection-only schema newTestStore applies lacks that table, so those tests open a
// full-schema fixture (every bounded context's DDL) via testdb/full instead. testdb/full is the sanctioned cross-context schema surface
// (arch-go allows **.testdb here); it takes *testing.T, so this helper is test-only (no benchmark variant needed).
func newFullSchemaStore(t *testing.T) *mysql.Store {
	t.Helper()
	s, err := mysql.New(full.Open(t))
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

// TestStore_InsertEventsAt_DuplicateStampsPersistedIngestedAt pins the batched-insert behavior: a duplicate event_id (dropped by
// INSERT IGNORE) keeps the ingested_at_ns from its FIRST insert, and the caller's slice is stamped with that persisted value, not
// the current batch's. A genuinely-new row in the same batch still gets the current batch's time.
func TestStore_InsertEventsAt_DuplicateStampsPersistedIngestedAt(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	first := []api.Event{{EventID: "dup-1", HostID: "h", TimestampNs: 100, EventType: "fork", Payload: json.RawMessage(`{}`)}}
	require.NoError(t, s.InsertEventsAt(ctx, first, 1000))
	require.Equal(t, int64(1000), first[0].IngestedAtNs)

	second := []api.Event{
		{EventID: "dup-1", HostID: "h", TimestampNs: 100, EventType: "fork", Payload: json.RawMessage(`{}`)},
		{EventID: "dup-2", HostID: "h", TimestampNs: 200, EventType: "fork", Payload: json.RawMessage(`{}`)},
	}
	require.NoError(t, s.InsertEventsAt(ctx, second, 2000))
	assert.Equal(t, int64(1000), second[0].IngestedAtNs, "duplicate keeps its original persisted ingested_at_ns, not the new batch's 2000")
	assert.Equal(t, int64(2000), second[1].IngestedAtNs, "newly inserted row in the same batch gets the new ingest time")

	count, err := s.CountEvents(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count, "dup-1 deduped; only dup-2 added")
}

// TestStore_InsertEventsAt_ChunksLargeBatch inserts more events than eventInsertChunkRows so the multi-row INSERT spans more than
// one chunk, and asserts every row across the chunk boundary is persisted and stamped.
func TestStore_InsertEventsAt_ChunksLargeBatch(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	const n = 600 // > eventInsertChunkRows (500): forces two chunks
	events := make([]api.Event, n)
	for i := range events {
		events[i] = api.Event{EventID: "chunk-" + strconv.Itoa(i), HostID: "h", TimestampNs: int64(i + 1), EventType: "fork", Payload: json.RawMessage(`{}`)}
	}
	require.NoError(t, s.InsertEventsAt(ctx, events, 7777))
	for i := range events {
		require.Equal(t, int64(7777), events[i].IngestedAtNs, "row %d across the chunk boundary must be stamped", i)
	}

	count, err := s.CountEvents(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(n), count)
}

func TestStore_InsertEvents_EmptyIsNoOp(t *testing.T) {
	// The empty-slice fast path returns nil without touching the DB. Important for the retry wrapper: an empty insert must
	// not waste a deadlock-retry budget on a no-op transaction.
	s := newTestStore(t)
	ctx := t.Context()

	require.NoError(t, s.InsertEvents(ctx, nil), "InsertEvents(nil) is a no-op")
	require.NoError(t, s.InsertEvents(ctx, []api.Event{}), "InsertEvents([]) is a no-op")
	require.NoError(t, s.InsertEventsAt(ctx, nil, 1234), "InsertEventsAt(nil, _) is a no-op")

	count, err := s.CountEvents(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count, "no rows inserted by any of the no-op calls")
}

func TestStore_InsertEvents_ClosedDBReturnsError(t *testing.T) {
	// Closing the underlying db pool forces BeginTxx to fail on the first attempt. The deadlock-retry wrapper must NOT
	// retry this class of error (it is not a 1213), so the call should return promptly with the begin-tx error wrapped.
	s := newTestStore(t)
	require.NoError(t, s.DB().Close(), "close underlying pool to force begin-tx failure")

	events := []api.Event{
		{EventID: "closed-db-1", HostID: "h", TimestampNs: 1, EventType: "fork", Payload: json.RawMessage(`{}`)},
	}
	err := s.InsertEvents(t.Context(), events)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "begin tx", "begin tx failures must propagate, not be swallowed by the retry loop")
}

// spec:server-event-ingestion/horizontally-scalable-ingestion-service/two-ingestion-replicas-run-against-the-same-database
//
// Concurrent-InsertEvents stress test. Spawns N goroutines that each call InsertEvents with overlapping batches against
// the SAME *mysql.Store (which models two ingestion replicas pointing at one shared MySQL backend, since the handler is
// stateless apart from its store handle and both replicas would dial the same DB). Half the batches share event_ids
// with each other and with the other half, exercising both the INSERT IGNORE deduplication path and the M10 deadlock-
// retry wrapper under contention.
//
// Assertions:
//
//   - Every goroutine completes without error. The M10 retry budget is 5 attempts; if a deadlock window cannot resolve
//     in that budget, the goroutine returns the wrapped 1213 and the test fails loudly rather than silently dropping
//     events.
//   - The events table's final cardinality equals the count of distinct event_ids across all batches (not the SUM of
//     batch lengths). This pins both the dedup semantic AND the "no spurious deletes / rollbacks" property: a buggy
//     concurrent path that lost rows would show up as a low cardinality count here.
//
// The architectural property being pinned is the spec's "Multiple replicas of the ingestion service MUST be able to
// accept agent traffic concurrently against the same database without coordinating with each other." A literal two-
// process test (two scaledriver binaries against one server) belongs at the M12 scale layer (#232); this in-process
// stress test pins the wire-level concurrency-safety property that makes the multi-process shape work.
func TestStore_InsertEvents_ConcurrentReplicaShape(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := t.Context()

	const goroutines = 16
	const eventsPerBatch = 20
	const sharedEventCount = 8 // first 8 events overlap across every batch; remaining 12 are unique per goroutine

	// Build the shared (overlap) event slice once. Every goroutine reuses these event_ids, so concurrent inserts of the
	// same row exercise INSERT IGNORE under contention. Their host_ids match across goroutines too because in
	// production multiple replicas commonly receive batches from the same host on different connections.
	shared := make([]api.Event, sharedEventCount)
	for i := range shared {
		shared[i] = api.Event{
			EventID:     "shared-" + strconv.Itoa(i),
			HostID:      "host-shared",
			TimestampNs: int64(i + 1),
			EventType:   "fork",
			Payload:     json.RawMessage(`{}`),
		}
	}

	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for g := range goroutines {
		wg.Add(1)
		go func(replicaIdx int) {
			defer wg.Done()
			batch := append([]api.Event(nil), shared...)
			for i := sharedEventCount; i < eventsPerBatch; i++ {
				batch = append(batch, api.Event{
					EventID:     "rep-" + strconv.Itoa(replicaIdx) + "-evt-" + strconv.Itoa(i),
					HostID:      "host-rep-" + strconv.Itoa(replicaIdx),
					TimestampNs: int64(i + 1),
					EventType:   "fork",
					Payload:     json.RawMessage(`{}`),
				})
			}
			if err := s.InsertEvents(ctx, batch); err != nil {
				errs <- fmt.Errorf("replica %d: %w", replicaIdx, err)
			}
		}(g)
	}
	wg.Wait()
	close(errs)

	var collected []error
	for err := range errs {
		collected = append(collected, err)
	}
	require.Empty(t, collected, "no replica goroutine may surface an unretried deadlock or insert error")

	got, err := s.CountEvents(ctx)
	require.NoError(t, err)
	// Distinct event_ids = sharedEventCount + goroutines * the per-batch unique count (eventsPerBatch minus sharedEventCount).
	wantDistinct := int64(sharedEventCount + (eventsPerBatch-sharedEventCount)*goroutines)
	assert.Equal(t, wantDistinct, got,
		"final events table cardinality must equal the distinct-event-id union across replicas")
}

// spec:server-event-ingestion/event-storage-drops-redundant-indexes/the-unprocessed-event-claim-still-works-after-the-index-diet
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

// spec:server-detection-rules-engine/persisted-alert-schema/an-alert-with-no-attributable-process-omits-the-process-link
// spec:server-detection-rules-engine/alert-dedup-by-subject/process-less-findings-dedup-on-a-rule-supplied-subject
// TestStore_InsertAlert_ProcessLess covers the ADR-0008-amendment persistence path: a process-less alert (ProcessID 0, a rule-supplied
// Subject) persists with a NULL process_id (no fk_alerts_process violation) and dedups on subject rather than process_id. The same
// daemon registration dedups; a different one produces a second alert; the row reads back with ProcessID 0 via the read-path COALESCE.
func TestStore_InsertAlert_ProcessLess(t *testing.T) {
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
