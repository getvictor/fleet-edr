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

	"github.com/fleetdm/edr/server/detection/internal/pipeline"
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

	rec := &recordingMetrics{}
	runRetention(t, f.db, 0, 180, rec)

	for _, id := range expired {
		assert.False(t, f.exists("alerts", id), "an alert past the window is pruned")
		assert.Zero(t, f.eventLinks(id), "and its event links with it")
	}
	assert.True(t, f.exists("alerts", inside), "an alert inside the window survives")
	assert.True(t, f.exists("alerts", justInside), "an alert a minute inside the window survives")
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

	t.Run("process pruning off, alert pruning on", func(t *testing.T) {
		t.Parallel()
		f := newAlertFixture(t)
		expired := f.alert(181*day, 0, 1)
		oldProc := f.completedProcess()

		runRetention(t, f.db, 0, 180, nil)

		assert.False(t, f.exists("alerts", expired), "the alert window still prunes with the process window disabled")
		assert.True(t, f.exists("processes", oldProc), "and the disabled process window prunes nothing")
	})

	t.Run("alert pruning off, process pruning on", func(t *testing.T) {
		t.Parallel()
		f := newAlertFixture(t)
		expired := f.alert(181*day, 0, 1)
		oldProc := f.completedProcess()

		runRetention(t, f.db, 30, 0, nil)

		assert.True(t, f.exists("alerts", expired), "a disabled alert window keeps the alert")
		assert.False(t, f.exists("processes", oldProc), "while the process window still prunes")
	})

	t.Run("a shorter process window does not shorten the alert window", func(t *testing.T) {
		t.Parallel()
		f := newAlertFixture(t)
		inAlertWindow := f.alert(90*day, 0, 1) // past a 30-day process window, inside a 180-day alert window

		runRetention(t, f.db, 30, 180, nil)

		assert.True(t, f.exists("alerts", inAlertWindow), "the alert window, not the process window, decides an alert's fate")
	})
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
