//go:build integration

// Integration coverage for alert retention (issue #995), against real MySQL: alerts expire on their own window measured from their last
// triage activity, independently of the process window in both directions, and an expired alert releases the process row it pinned.

package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	detectionmysql "github.com/fleetdm/edr/server/detection/internal/mysql"
	"github.com/fleetdm/edr/server/detection/internal/pipeline"
	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
	"github.com/fleetdm/edr/server/testdb/full"
)

// retentionNow is the fixed "now" every alert retention test runs at, so the cutoff is exact rather than a moving target.
var retentionNow = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

type alertFixture struct {
	db  *sqlx.DB
	t   *testing.T
	seq int
}

// alert inserts an alert whose last triage activity was lastActivity ago, links it to linkedEvents events, and optionally to a process.
// updated_at is set explicitly because MySQL would otherwise stamp the real wall clock, which has nothing to do with the injected now.
//
// Every alert gets event links by default. A real alert always has them, and they are what make a naive DELETE FROM alerts fail: the
// alert_events foreign key has no ON DELETE CASCADE. An alert fixture with no links would hide that entirely.
func (f *alertFixture) alert(lastActivity time.Duration, processID int64, linkedEvents int) int64 {
	f.t.Helper()
	f.seq++
	var proc any
	if processID > 0 {
		proc = processID
	}
	res, err := f.db.ExecContext(context.Background(), `
		INSERT INTO alerts (host_id, rule_id, severity, title, description, subject, process_id)
		VALUES ('host-ret', 'r1', 'high', 't', 'd', ?, ?)`, fmt.Sprintf("subject-%d", f.seq), proc)
	require.NoError(f.t, err)
	id, err := res.LastInsertId()
	require.NoError(f.t, err)
	stamp := retentionNow.Add(-lastActivity)
	_, err = f.db.ExecContext(context.Background(), `UPDATE alerts SET created_at = ?, updated_at = ? WHERE id = ?`, stamp, stamp, id)
	require.NoError(f.t, err)
	for i := range linkedEvents {
		_, err := f.db.ExecContext(context.Background(), `INSERT INTO alert_events (alert_id, event_id) VALUES (?, ?)`,
			id, fmt.Sprintf("evt-%d-%d", id, i))
		require.NoError(f.t, err)
	}
	return id
}

// completedProcess inserts a process that exited long enough ago to be past any process window these tests use.
func (f *alertFixture) completedProcess() int64 {
	f.t.Helper()
	exit := retentionNow.Add(-400 * 24 * time.Hour).UnixNano()
	res, err := f.db.ExecContext(context.Background(), `
		INSERT INTO processes (host_id, pid, ppid, path, fork_time_ns, exit_time_ns, is_snapshot)
		VALUES ('host-ret', 0, 0, '/bin/x', ?, ?, false)`, exit-1, exit)
	require.NoError(f.t, err)
	id, err := res.LastInsertId()
	require.NoError(f.t, err)
	return id
}

func (f *alertFixture) exists(table string, id int64) bool {
	f.t.Helper()
	var n int
	require.NoError(f.t, f.db.GetContext(context.Background(), &n, `SELECT COUNT(*) FROM `+table+` WHERE id = ?`, id))
	return n == 1
}

func (f *alertFixture) eventLinks(alertID int64) int {
	f.t.Helper()
	var n int
	require.NoError(f.t, f.db.GetContext(context.Background(), &n, `SELECT COUNT(*) FROM alert_events WHERE alert_id = ?`, alertID))
	return n
}

func newAlertFixture(t *testing.T) *alertFixture {
	t.Helper()
	return &alertFixture{db: full.Open(t), t: t}
}

func runRetention(t *testing.T, db *sqlx.DB, processDays, alertDays int, rec *recordingMetrics) {
	t.Helper()
	opts := pipeline.RetentionOptions{
		RetentionDays:      processDays,
		AlertRetentionDays: alertDays,
		Now:                func() time.Time { return retentionNow },
		BatchSize:          2, // small, so a multi-batch pass is exercised by the same fixtures
	}
	if rec != nil {
		opts.Metrics = rec
	}
	_, err := pipeline.NewRetention(db, opts).Run(t.Context())
	require.NoError(t, err)
}

// spec:server-detection-rules-engine/alerts-expire-on-their-own-window/an-alert-past-the-window-is-pruned-and-one-inside-it-survives
//
// TestAlertRetention_PrunesPastTheWindowAndKeepsInside pins BOTH sides of the boundary, since an off-by-one here silently deletes
// evidence. Several expired alerts with a batch size of 2 also make the pass run more than one batch.
func TestAlertRetention_PrunesPastTheWindowAndKeepsInside(t *testing.T) {
	t.Parallel()
	f := newAlertFixture(t)
	const day = 24 * time.Hour

	var expired []int64
	for range 5 {
		expired = append(expired, f.alert(181*day, 0, 3))
	}
	inside := f.alert(179*day, 0, 3)
	justInside := f.alert(180*day-time.Minute, 0, 3)
	// Exactly at the cutoff is not OLDER than the window, so it stays. The fixed clock makes the stamp equal the cutoff to the
	// microsecond, which is what lets a `<=` in the prune's predicate fail this test rather than pass it.
	atTheCutoff := f.alert(180*day, 0, 3)

	rec := &recordingMetrics{}
	runRetention(t, f.db, 0, 180, rec)

	for _, id := range expired {
		assert.False(t, f.exists("alerts", id), "an alert past the window is pruned")
		assert.Zero(t, f.eventLinks(id), "and its event links with it")
	}
	assert.True(t, f.exists("alerts", inside), "an alert inside the window survives")
	assert.True(t, f.exists("alerts", justInside), "an alert a minute inside the window survives")
	assert.True(t, f.exists("alerts", atTheCutoff), "an alert exactly at the cutoff is not older than the window, and survives")
	assert.Equal(t, 3, f.eventLinks(inside), "a surviving alert keeps every event link")

	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.Equal(t, int64(5), rec.alertRowsDeleted, "the alert metric counts every batch, not just the last")
	assert.Zero(t, rec.processRowsDeleted, "and the process metric is not credited with them")
}

// spec:server-detection-rules-engine/alerts-expire-on-their-own-window/an-alert-raised-long-ago-but-recently-triaged-is-kept
//
// TestAlertRetention_MeasuresFromLastTriageActivity: an alert raised long ago but touched inside the window is somebody's live
// investigation and is kept. Deleting on creation age would take the evidence out from under them.
func TestAlertRetention_MeasuresFromLastTriageActivity(t *testing.T) {
	t.Parallel()
	f := newAlertFixture(t)
	const day = 24 * time.Hour

	acknowledgedRecently := f.alert(400*day, 0, 1)
	_, err := f.db.ExecContext(t.Context(), `UPDATE alerts SET status = 'acknowledged', updated_at = ? WHERE id = ?`,
		retentionNow.Add(-10*day), acknowledgedRecently)
	require.NoError(t, err)

	runRetention(t, f.db, 0, 180, nil)

	assert.True(t, f.exists("alerts", acknowledgedRecently),
		"an alert raised 400 days ago but acknowledged 10 days ago is still being worked, and is kept")
}

// spec:server-detection-rules-engine/alerts-expire-on-their-own-window/an-expired-alert-releases-the-process-row-it-pinned
//
// TestAlertRetention_ReleasesThePinnedProcessRow is the assertion that catches the two prunes wired in the wrong order or not at all.
// The process prune skips any row an alert references; once the alert expires the row must become collectable, and one still pinned by
// a surviving alert must not. The runner prunes alerts first, so the release lands in the same pass.
func TestAlertRetention_ReleasesThePinnedProcessRow(t *testing.T) {
	t.Parallel()
	f := newAlertFixture(t)
	const day = 24 * time.Hour

	releasedProc := f.completedProcess()
	f.alert(181*day, releasedProc, 1)
	pinnedProc := f.completedProcess()
	f.alert(10*day, pinnedProc, 1)

	runRetention(t, f.db, 30, 180, nil)

	assert.False(t, f.exists("processes", releasedProc), "a process pinned only by an expired alert is collected in the same pass")
	assert.True(t, f.exists("processes", pinnedProc), "a process pinned by a surviving alert stays, so its pivot still works")
}

// spec:server-detection-rules-engine/alerts-expire-on-their-own-window/a-disabled-window-prunes-nothing
//
// TestAlertRetention_ZeroDisablesTheAlertPrune: 0 is the documented way to keep today's behaviour, never prune alerts.
func TestAlertRetention_ZeroDisablesTheAlertPrune(t *testing.T) {
	t.Parallel()
	f := newAlertFixture(t)
	ancient := f.alert(3650*24*time.Hour, 0, 1)

	runRetention(t, f.db, 30, 0, nil)

	assert.True(t, f.exists("alerts", ancient), "a disabled alert window keeps even a ten-year-old alert")
}

// spec:server-detection-rules-engine/alerts-expire-on-their-own-window/the-alert-window-is-independent-of-the-process-window
//
// TestAlertRetention_IsIndependentOfTheProcessWindow catches the implementation slip the issue names: hanging alerts off the existing
// knob. Each direction is its own case. The first is the one an early return in the runner would have broken silently: an operator who
// disables process pruning for a forensic hold has not decided to keep every alert.
func TestAlertRetention_IsIndependentOfTheProcessWindow(t *testing.T) {
	t.Parallel()
	const day = 24 * time.Hour

	// Every case seeds the same two rows, an unpinned process past any process window and an alert of the given age, and asserts both,
	// so each direction shows the other window left alone.
	cases := []struct {
		name          string
		processDays   int
		alertDays     int
		alertAge      time.Duration
		wantAlertKept bool
		wantProcKept  bool
	}{
		{
			name: "process pruning off, alert pruning on", processDays: 0, alertDays: 180, alertAge: 181 * day,
			wantAlertKept: false, wantProcKept: true,
		},
		{
			name: "alert pruning off, process pruning on", processDays: 30, alertDays: 0, alertAge: 181 * day,
			wantAlertKept: true, wantProcKept: false,
		},
		// Past a 30-day process window but inside a 180-day alert window: the alert window, not the process window, decides.
		{
			name: "a shorter process window does not shorten the alert window", processDays: 30, alertDays: 180, alertAge: 90 * day,
			wantAlertKept: true, wantProcKept: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newAlertFixture(t)
			alertID := f.alert(tc.alertAge, 0, 1)
			procID := f.completedProcess()

			runRetention(t, f.db, tc.processDays, tc.alertDays, nil)

			assert.Equal(t, tc.wantAlertKept, f.exists("alerts", alertID), "alert kept")
			assert.Equal(t, tc.wantProcKept, f.exists("processes", procID), "process kept")
		})
	}
}

// TestAlertRetention_Loop_RunsWhenOnlyTheAlertWindowIsSet: Loop used to return immediately whenever the process window was 0, back when
// that was the runner's only job. With alerts on their own knob that early return would have disabled alert pruning outright for
// anyone who set EDR_RETENTION_DAYS=0. Run is covered above; this pins that Loop does not bail before calling it.
func TestAlertRetention_Loop_RunsWhenOnlyTheAlertWindowIsSet(t *testing.T) {
	t.Parallel()
	f := newAlertFixture(t)
	expired := f.alert(181*24*time.Hour, 0, 1)

	ctx, cancel := context.WithCancel(t.Context())
	runner := pipeline.NewRetention(f.db, pipeline.RetentionOptions{
		RetentionDays:      0,
		AlertRetentionDays: 180,
		Interval:           time.Hour, // runPeriodic runs one pass immediately, then waits
		Now:                func() time.Time { return retentionNow },
	})
	done := make(chan struct{})
	go func() {
		runner.Loop(ctx)
		close(done)
	}()

	require.Eventually(t, func() bool { return !f.exists("alerts", expired) }, 10*time.Second, 50*time.Millisecond,
		"Loop must run the alert prune even though the process window is disabled")
	cancel()
	<-done
}

// spec:server-detection-rules-engine/alerts-expire-on-their-own-window/a-re-fire-during-a-prune-completes-cleanly
//
// TestAlertRetention_ARefireDuringThePruneCompletesCleanly pins what the prune's FOR UPDATE buys, by staging the interleaving that needs
// it: a re-fire has already claimed the expired alert's row through InsertAlert's dedup statement and is about to link its evidence
// when the prune starts.
//
// With the lock the prune waits at its SELECT, the re-fire links and commits, and the prune then removes the alert with every link,
// including the one just added. Without it the prune does not wait there. It deletes the existing links, taking next-key locks on that
// range of alert_events, and then waits on the alert row the re-fire holds, while the re-fire waits on those gap locks to insert its
// link. InnoDB resolves that deadlock by rolling one of them back, so either the detection write or the retention pass fails.
//
// The staging is deterministic rather than a timing race: the re-fire does not link until performance_schema shows the prune blocked
// on a lock inside this test's own database.
func TestAlertRetention_ARefireDuringThePruneCompletesCleanly(t *testing.T) {
	t.Parallel()
	f := newAlertFixture(t)
	ctx := t.Context()
	expired := f.alert(181*24*time.Hour, 0, 2)

	// The first half of InsertAlert's dedup path, held open on its own connection. subject-1 is the fixture's first subject, so this
	// collides with the expired alert on the dedup key exactly as a re-fire of the same finding would.
	refire, err := f.db.BeginTxx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = refire.Rollback() }()
	_, err = refire.ExecContext(ctx, `
		INSERT INTO alerts (host_id, rule_id, severity, title, description, subject)
		VALUES ('host-ret', 'r1', 'high', 't', 'd', 'subject-1')
		ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id), updated_at = updated_at`)
	require.NoError(t, err)

	pruned := make(chan error, 1)
	go func() {
		_, runErr := pipeline.NewRetention(f.db, pipeline.RetentionOptions{
			AlertRetentionDays: 180,
			Now:                func() time.Time { return retentionNow },
		}).Run(ctx)
		pruned <- runErr
	}()

	waitForLockWait(t, f.db, "the prune must reach a lock the re-fire holds before the re-fire links its evidence")

	_, linkErr := refire.ExecContext(ctx, `INSERT IGNORE INTO alert_events (alert_id, event_id) VALUES (?, 'evt-refire')`, expired)
	commitErr := refire.Commit()

	select {
	case runErr := <-pruned:
		require.NoError(t, runErr, "the retention pass must not be the deadlock victim")
	case <-time.After(30 * time.Second):
		t.Fatal("the retention pass did not finish")
	}
	require.NoError(t, linkErr, "the re-fire's evidence link must not be the deadlock victim")
	require.NoError(t, commitErr)

	assert.False(t, f.exists("alerts", expired), "the expired alert is pruned: a re-fire is not triage activity")
	assert.Zero(t, f.eventLinks(expired), "with every link, including the one the re-fire added, so nothing is left orphaned")
}

// TestAlertRetention_AFailedBatchLeavesTheAlertWhole pins why each batch is a transaction. A batch deletes an alert's event links before
// the alert itself, so a failure between the two must roll the links back: otherwise a pass that failed would still have stripped the
// evidence from alerts it then kept. It also pins that the failure reaches the caller, rather than a pass reporting success.
func TestAlertRetention_AFailedBatchLeavesTheAlertWhole(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		stage func(t *testing.T, f *alertFixture, alertID int64) context.Context
	}{
		{
			// A test-only table referencing the alert makes the second DELETE fail on its foreign key, after the first has run.
			name: "the alert delete fails after its links were deleted",
			stage: func(t *testing.T, f *alertFixture, alertID int64) context.Context {
				t.Helper()
				_, err := f.db.ExecContext(t.Context(),
					`CREATE TABLE retention_blocker (alert_id BIGINT NOT NULL, FOREIGN KEY (alert_id) REFERENCES alerts (id))`)
				require.NoError(t, err)
				_, err = f.db.ExecContext(t.Context(), `INSERT INTO retention_blocker (alert_id) VALUES (?)`, alertID)
				require.NoError(t, err)
				return t.Context()
			},
		},
		{
			name: "the batch cannot start",
			stage: func(t *testing.T, _ *alertFixture, _ int64) context.Context {
				t.Helper()
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				return ctx
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newAlertFixture(t)
			expired := f.alert(181*24*time.Hour, 0, 3)
			ctx := tc.stage(t, f, expired)

			rec := &recordingMetrics{}
			_, err := pipeline.NewRetention(f.db, pipeline.RetentionOptions{
				AlertRetentionDays: 180,
				Now:                func() time.Time { return retentionNow },
				Metrics:            rec,
			}).Run(ctx)

			require.Error(t, err, "a failed batch must fail the pass")
			assert.True(t, f.exists("alerts", expired), "the alert the batch could not delete is still there")
			assert.Equal(t, 3, f.eventLinks(expired), "with every event link it had, because the batch rolled back")
			rec.mu.Lock()
			defer rec.mu.Unlock()
			assert.Zero(t, rec.alertRowsDeleted, "and nothing is counted as deleted")
		})
	}
}

// waitForLockWait blocks until some statement in this test's own database is waiting on a row lock, which is how the staged
// concurrency tests below know the other side has reached the point they need it at, rather than guessing with a sleep.
func waitForLockWait(t *testing.T, db *sqlx.DB, msg string) {
	t.Helper()
	require.Eventually(t, func() bool {
		var waiting int
		err := db.GetContext(t.Context(), &waiting, `
			SELECT COUNT(*) FROM performance_schema.data_lock_waits w
			JOIN performance_schema.data_locks l ON l.ENGINE_LOCK_ID = w.REQUESTING_ENGINE_LOCK_ID
			WHERE l.OBJECT_SCHEMA = DATABASE()`)
		return err == nil && waiting > 0
	}, 10*time.Second, 20*time.Millisecond, msg)
}

// spec:server-detection-rules-engine/alerts-expire-on-their-own-window/triage-during-a-prune-keeps-the-alert-or-reports-it-gone
//
// TestAlertRetention_TriageRacingThePrune stages both orders of an analyst changing an alert's status while retention expires it. Each
// side is the real code for the half under test, and the other side is its statements held open on a second connection, so the
// interleaving is fixed rather than timed.
func TestAlertRetention_TriageRacingThePrune(t *testing.T) {
	t.Parallel()
	const day = 24 * time.Hour

	t.Run("the prune takes the alert first, and triage reports it gone", func(t *testing.T) {
		t.Parallel()
		f := newAlertFixture(t)
		ctx := t.Context()
		store, err := detectionmysql.New(f.db, detectiontestkit.NewMemArchive(), nil)
		require.NoError(t, err)
		expired := f.alert(181*day, 0, 2)

		// The prune's batch for this one alert, held before commit.
		prune, err := f.db.BeginTxx(ctx, nil)
		require.NoError(t, err)
		defer func() { _ = prune.Rollback() }()
		var locked []int64
		require.NoError(t, prune.SelectContext(ctx, &locked, `SELECT id FROM alerts WHERE id = ? FOR UPDATE`, expired))
		_, err = prune.ExecContext(ctx, `DELETE FROM alert_events WHERE alert_id = ?`, expired)
		require.NoError(t, err)
		_, err = prune.ExecContext(ctx, `DELETE FROM alerts WHERE id = ?`, expired)
		require.NoError(t, err)

		triaged := make(chan error, 1)
		go func() { triaged <- store.UpdateAlertStatus(ctx, expired, api.AlertStatusAcknowledged, "") }()
		waitForLockWait(t, f.db, "triage must be waiting on the alert the prune holds")
		require.NoError(t, prune.Commit())

		select {
		case err := <-triaged:
			// Not-found is what the API turns into a 404. Anything else here surfaced to the analyst as an internal error.
			require.ErrorIs(t, err, api.ErrAlertNotFound, "triage on an alert the prune deleted must report it gone, got %v", err)
		case <-time.After(30 * time.Second):
			t.Fatal("triage did not finish")
		}
	})

	t.Run("triage takes the alert first, and the prune keeps it", func(t *testing.T) {
		t.Parallel()
		f := newAlertFixture(t)
		ctx := t.Context()
		expired := f.alert(181*day, 0, 2)

		// UpdateAlertStatus's statements, held before commit. The UPDATE refreshes updated_at to the wall clock, which is long after the
		// fixed retention clock's cutoff: acknowledging the alert is exactly the triage activity that puts it back inside the window.
		triage, err := f.db.BeginTxx(ctx, nil)
		require.NoError(t, err)
		defer func() { _ = triage.Rollback() }()
		var status string
		require.NoError(t, triage.GetContext(ctx, &status, `SELECT status FROM alerts WHERE id = ? FOR UPDATE`, expired))
		_, err = triage.ExecContext(ctx, `UPDATE alerts SET status = 'acknowledged' WHERE id = ?`, expired)
		require.NoError(t, err)

		pruned := make(chan error, 1)
		go func() {
			_, runErr := pipeline.NewRetention(f.db, pipeline.RetentionOptions{
				AlertRetentionDays: 180,
				Now:                func() time.Time { return retentionNow },
			}).Run(ctx)
			pruned <- runErr
		}()
		waitForLockWait(t, f.db, "the prune must be waiting on the alert triage holds")
		require.NoError(t, triage.Commit())

		select {
		case err := <-pruned:
			require.NoError(t, err)
		case <-time.After(30 * time.Second):
			t.Fatal("the retention pass did not finish")
		}
		assert.True(t, f.exists("alerts", expired), "an alert acknowledged before the prune read it is inside the window again, and kept")
		assert.Equal(t, 2, f.eventLinks(expired), "with its evidence")
	})
}

// monitorRecord inserts a monitor record (issue #994) last written lastActivity ago: the alert fixture with the disposition switched,
// so the two differ in nothing but the column the prunes are scoped by.
func (f *alertFixture) monitorRecord(lastActivity time.Duration, linkedEvents int) int64 {
	f.t.Helper()
	id := f.alert(lastActivity, 0, linkedEvents)
	// updated_at restated: the UPDATE would otherwise refresh it to the wall clock and undo the fixture's age.
	_, err := f.db.ExecContext(context.Background(), `UPDATE alerts SET disposition = 'monitor', updated_at = updated_at WHERE id = ?`, id)
	require.NoError(f.t, err)
	return id
}

// runWindows runs one retention pass with every window set explicitly.
func runWindows(t *testing.T, db *sqlx.DB, processDays, alertDays, monitorDays int, rec *recordingMetrics) {
	t.Helper()
	opts := pipeline.RetentionOptions{
		RetentionDays:              processDays,
		AlertRetentionDays:         alertDays,
		MonitorRecordRetentionDays: monitorDays,
		Now:                        func() time.Time { return retentionNow },
		BatchSize:                  2,
	}
	if rec != nil {
		opts.Metrics = rec
	}
	_, err := pipeline.NewRetention(db, opts).Run(t.Context())
	require.NoError(t, err)
}

// spec:server-detection-rules-engine/monitor-mode-matches-are-kept-as-records/monitor-records-and-alerts-expire-on-their-own-windows
//
// TestMonitorRecordRetention_EachWindowPrunesOnlyItsOwnDisposition is the assertion that catches the likely slip the issue names: the two
// windows wired to the same rows. Every age is chosen to sit on opposite sides of the two cutoffs, so either prune reaching into the
// other's disposition deletes a row this test requires to survive.
func TestMonitorRecordRetention_EachWindowPrunesOnlyItsOwnDisposition(t *testing.T) {
	t.Parallel()
	f := newAlertFixture(t)
	const day = 24 * time.Hour

	expiredRecords := []int64{f.monitorRecord(8*day, 2), f.monitorRecord(9*day, 2), f.monitorRecord(10*day, 2)}
	freshRecord := f.monitorRecord(6*day, 2)
	alertPastMonitorWindow := f.alert(8*day, 0, 2)
	expiredAlert := f.alert(181*day, 0, 2)

	rec := &recordingMetrics{}
	runWindows(t, f.db, 0, 180, 7, rec)

	for _, id := range expiredRecords {
		assert.False(t, f.exists("alerts", id), "a monitor record past its window is pruned")
		assert.Zero(t, f.eventLinks(id), "with its event links")
	}
	assert.True(t, f.exists("alerts", freshRecord), "a monitor record inside its window is kept, however the alert window is set")
	assert.True(t, f.exists("alerts", alertPastMonitorWindow), "an alert past the monitor window but inside its own is kept")
	assert.False(t, f.exists("alerts", expiredAlert), "an alert past its own window is still pruned")

	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.Equal(t, int64(3), rec.monitorRecordRowsDeleted, "monitor records are counted on their own metric, across batches")
	assert.Equal(t, int64(1), rec.alertRowsDeleted, "and alerts on theirs")
}

// spec:server-detection-rules-engine/monitor-mode-matches-are-kept-as-records/a-zero-monitor-record-window-prunes-no-monitor-record
//
// TestMonitorRecordRetention_ZeroDisablesTheMonitorPrune: with the monitor window at 0 a monitor record of any age is kept, even one far
// past the alert window that is enabled in the same pass.
func TestMonitorRecordRetention_ZeroDisablesTheMonitorPrune(t *testing.T) {
	t.Parallel()
	f := newAlertFixture(t)
	ancient := f.monitorRecord(400*24*time.Hour, 1)

	runWindows(t, f.db, 30, 180, 0, nil)

	assert.True(t, f.exists("alerts", ancient), "a disabled monitor window keeps the record, and the alert window does not reach it")
}

// TestMonitorRecordRetention_Loop_RunsWhenOnlyTheMonitorWindowIsSet is the monitor-record counterpart of the alert Loop test above. Loop
// returns early only when every window is off, and the tests that call Run directly cannot see that check: dropping the monitor window
// from it would silently disable monitor-record pruning for anyone who turned both other windows off, and they would all still pass.
func TestMonitorRecordRetention_Loop_RunsWhenOnlyTheMonitorWindowIsSet(t *testing.T) {
	t.Parallel()
	f := newAlertFixture(t)
	expired := f.monitorRecord(8*24*time.Hour, 1)

	ctx, cancel := context.WithCancel(t.Context())
	runner := pipeline.NewRetention(f.db, pipeline.RetentionOptions{
		RetentionDays:              0,
		AlertRetentionDays:         0,
		MonitorRecordRetentionDays: 7,
		Interval:                   time.Hour, // runPeriodic runs one pass immediately, then waits
		Now:                        func() time.Time { return retentionNow },
	})
	done := make(chan struct{})
	go func() {
		runner.Loop(ctx)
		close(done)
	}()

	require.Eventually(t, func() bool { return !f.exists("alerts", expired) }, 10*time.Second, 50*time.Millisecond,
		"Loop must run the monitor-record prune even though both other windows are disabled")
	cancel()
	<-done
}
