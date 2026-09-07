//go:build integration

package tests

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/fleetdm/edr/server/coordination/leader"
	rulesapi "github.com/fleetdm/edr/server/rules/api"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/bootstrap"
)

// insertAlertWithOrigin writes one alert directly, so a test can stage the pre-attribution state the backfill exists to fix:
// rows whose origin was never recorded because they predate the column being populated.
func insertAlertWithOrigin(t *testing.T, ctx context.Context, d *bootstrap.Detection, ruleID, origin, subject string) int64 {
	t.Helper()
	// A distinct subject per row, because alerts carries a dedup unique key over (source, host_id, rule_id, subject): two alerts
	// for one rule on one host are the SAME alert unless they name different subjects, which is the schema telling the fixture
	// what a realistic pair looks like.
	res, err := d.Store().DB().ExecContext(ctx,
		`INSERT INTO alerts (host_id, rule_id, source, severity, title, description, origin, subject, techniques)
		 VALUES (?, ?, 'detection', 'high', 'seeded', 'seeded', ?, ?, '[]')`,
		"host-827", ruleID, origin, subject)
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

// insertAppControlAlert writes the row an application-control block really produces: the operator's own policy entry as the rule
// id, under the application_control source.
func insertAppControlAlert(t *testing.T, ctx context.Context, d *bootstrap.Detection, ruleID, subject string) int64 {
	t.Helper()
	res, err := d.Store().DB().ExecContext(ctx,
		`INSERT INTO alerts (host_id, rule_id, source, severity, title, description, origin, subject, techniques)
		 VALUES (?, ?, 'application_control', 'high', 'Application blocked', 'seeded', '', ?, '[]')`,
		"host-827", ruleID, subject)
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

func originOfAlert(t *testing.T, ctx context.Context, d *bootstrap.Detection, id int64) string {
	t.Helper()
	var origin string
	require.NoError(t, d.Store().DB().GetContext(ctx, &origin, `SELECT origin FROM alerts WHERE id = ?`, id))
	return origin
}

// spec:server-detection-rules-engine/alerts-from-vendored-rules-are-credited/an-uncredited-alert-is-credited
// spec:server-detection-rules-engine/alerts-from-vendored-rules-are-credited/a-recorded-attribution-is-not-overwritten
//
// TestBackfillAlertOrigins covers issue #827, and the two rows that must NOT change are the reason it exists as a test rather
// than a one-line UPDATE.
//
// Filling every empty origin would be the obvious implementation and would be wrong twice over. Our own rules' historical alerts
// must stay empty, because migration 00012 deliberately distinguishes "raised before attribution existed" from "raised by us", and
// filling them destroys that distinction irreversibly. A projection's alerts must stay empty because its rule_id is the operator's
// own policy entry, so crediting this project for it claims authorship of their blocklist; that is the bug review caught in #824.
func TestBackfillAlertOrigins(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})

	vendored := insertAlertWithOrigin(t, ctx, d, "proc_creation_macos_applescript", "", `{"pid":1}`)
	ours := insertAlertWithOrigin(t, ctx, d, "suspicious_exec", "", `{"pid":2}`)
	// The shape an application-control block ACTUALLY persists: the alert carries the operator's policy entry id
	// (`app_control:<n>`) and source `application_control`, not the catalog rule id. Review caught the first version of this row
	// using the catalog id, which the system never writes, so it asserted the exclusion against a shape that cannot occur.
	projection := insertAppControlAlert(t, ctx, d, "app_control:7", `{"pid":3}`)
	alreadyCredited := insertAlertWithOrigin(t, ctx, d, "proc_creation_macos_applescript", "Someone Else", `{"pid":4}`)

	// Only the vendored rule is in scope, which is the caller's decision and what the store is handed.
	updated, err := d.Store().BackfillAlertOrigins(ctx, map[string]string{
		"proc_creation_macos_applescript": "SigmaHQ",
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), updated, "exactly the one uncredited vendored alert")

	assert.Equal(t, "SigmaHQ", originOfAlert(t, ctx, d, vendored), "the vendored rule's alert is credited")
	assert.Empty(t, originOfAlert(t, ctx, d, ours),
		"our own rule's alert must stay empty, or the distinction migration 00012 preserves is destroyed")
	assert.Empty(t, originOfAlert(t, ctx, d, projection),
		"an application-control alert must stay empty: its rule id is the operator's own policy entry, so crediting it would "+
			"claim this project wrote their blocklist")
	assert.Equal(t, "Someone Else", originOfAlert(t, ctx, d, alreadyCredited),
		"an origin already recorded must never be overwritten")
}

// TestBackfillAlertOrigins_IsIdempotent pins that this can run on every boot, which is what makes a boot-time one-shot safe to
// leave in place rather than something to remove after one release.
func TestBackfillAlertOrigins_IsIdempotent(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})

	id := insertAlertWithOrigin(t, ctx, d, "proc_creation_macos_applescript", "", `{"pid":5}`)
	origins := map[string]string{"proc_creation_macos_applescript": "SigmaHQ"}

	first, err := d.Store().BackfillAlertOrigins(ctx, origins)
	require.NoError(t, err)
	require.Equal(t, int64(1), first)

	second, err := d.Store().BackfillAlertOrigins(ctx, origins)
	require.NoError(t, err)
	assert.Zero(t, second, "a second pass matches nothing, because only an empty origin is in scope")
	assert.Equal(t, "SigmaHQ", originOfAlert(t, ctx, d, id))
}

// TestBackfillAlertOrigins_EmptyScopeWritesNothing covers the deployment this is a no-op for: one running no vendored rules at
// all. It must not issue a statement whose CASE has no branches, which is a malformed query rather than an empty result.
func TestBackfillAlertOrigins_EmptyScopeWritesNothing(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})

	id := insertAlertWithOrigin(t, ctx, d, "suspicious_exec", "", `{"pid":6}`)
	updated, err := d.Store().BackfillAlertOrigins(ctx, nil)
	require.NoError(t, err)
	assert.Zero(t, updated)
	assert.Empty(t, originOfAlert(t, ctx, d, id))
}

// stubOriginRule is the smallest rule the scope decision reads: an id and a declared foreign origin.
type stubOriginRule struct{ id, origin string }

func (r stubOriginRule) ID() string           { return r.id }
func (r stubOriginRule) DisplayName() string  { return r.id }
func (r stubOriginRule) Techniques() []string { return nil }
func (r stubOriginRule) Origin() string       { return r.origin }
func (r stubOriginRule) Platforms() []rulesapi.Platform {
	return []rulesapi.Platform{rulesapi.PlatformDarwin}
}
func (r stubOriginRule) Doc() rulesapi.Documentation {
	return rulesapi.Documentation{Title: r.id, EventTypes: []string{"exec"}}
}
func (r stubOriginRule) SupportedExclusionMatchTypes() []rulesapi.ExclusionMatchType { return nil }
func (r stubOriginRule) Evaluate(context.Context, []rulesapi.Event, rulesapi.GraphReader) ([]rulesapi.Finding, error) {
	return nil, nil
}

// TestBackfillAlertOrigins_ThroughTheLeaderLock exercises the path an operator's upgrade actually takes, which the store test
// above does not: the bootstrap method decides scope, takes the lock, and reports whether this replica did the work.
//
// Worth its own test rather than trusting the two halves. The store is handed a prepared map, so nothing there proves the
// scope decision is wired to it, and DoOnceIfLeader is the difference between crediting alerts once and every replica racing to
// do it at boot.
func TestBackfillAlertOrigins_ThroughTheLeaderLock(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	coord := leader.NewMySQL(d.Store().DB(), slog.New(slog.DiscardHandler))

	vendored := insertAlertWithOrigin(t, ctx, d, "proc_creation_macos_applescript", "", `{"pid":10}`)
	ours := insertAlertWithOrigin(t, ctx, d, "suspicious_exec", "", `{"pid":11}`)

	ran, err := d.BackfillAlertOrigins(ctx, coord, []rulesapi.Rule{
		stubOriginRule{id: "proc_creation_macos_applescript", origin: "SigmaHQ"},
		plainRule{id: "suspicious_exec"},
	})
	require.NoError(t, err)
	assert.True(t, ran, "this replica held the lock, so it did the work")

	assert.Equal(t, "SigmaHQ", originOfAlert(t, ctx, d, vendored))
	assert.Empty(t, originOfAlert(t, ctx, d, ours), "a rule this project wrote is out of scope even through the full path")

	// Running again is the second boot, and it must not run the pass at all: the first one recorded that it finished (#872).
	ranAgain, err := d.BackfillAlertOrigins(ctx, coord, []rulesapi.Rule{
		stubOriginRule{id: "proc_creation_macos_applescript", origin: "SigmaHQ"},
	})
	require.NoError(t, err)
	assert.False(t, ranAgain, "the pass is recorded as done, so the second boot skips it rather than taking the lock again")
	assert.Equal(t, "SigmaHQ", originOfAlert(t, ctx, d, vendored))
}

// soleLeader stands in for the coordinator in the tests below, and it is not laziness about the real one: MySQL GET_LOCK names
// are global to the SERVER, not to a schema, so every test in this package taking `edr_alert_origin_backfill` from the real
// coordinator contends with every other one, and with anything else running against the same MySQL. Whichever test loses simply
// sees "another replica has it" and skips the pass, which reads as a failure of the behaviour under test.
//
// TestBackfillAlertOrigins_ThroughTheLeaderLock keeps the real coordinator, because the lock IS its subject. These tests are
// about what the recorded completion does, so they take the leadership as given and stay independent of each other.
type soleLeader struct{ leader.Coordinator }

func (soleLeader) DoOnceIfLeader(ctx context.Context, _ string, fn func(context.Context) error) (bool, error) {
	if err := fn(ctx); err != nil {
		return true, err
	}
	return true, nil
}

// spec:server-detection-rules-engine/alerts-from-vendored-rules-are-credited/a-start-after-a-completed-pass-reads-no-alerts
//
// TestBackfillAlertOrigins_ASecondStartReadsNoAlerts pins what durable completion buys, and it needs a probe row to be observable
// at all. The pass is idempotent, so "it ran again and changed nothing" and "it did not run" look identical from the alerts
// table. Seeding an uncredited row AFTER the first pass separates them: a pass that ran would credit it.
//
// That row is a probe rather than a scenario. It cannot occur in a running deployment, because every alert written since
// attribution shipped carries an origin, which is exactly why recording completion is sound.
func TestBackfillAlertOrigins_ASecondStartReadsNoAlerts(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	coord := soleLeader{}
	rules := []rulesapi.Rule{stubOriginRule{id: "proc_creation_macos_applescript", origin: "SigmaHQ"}}

	first := insertAlertWithOrigin(t, ctx, d, "proc_creation_macos_applescript", "", `{"pid":20}`)
	ran, err := d.BackfillAlertOrigins(ctx, coord, rules)
	require.NoError(t, err)
	require.True(t, ran)
	require.Equal(t, "SigmaHQ", originOfAlert(t, ctx, d, first))

	probe := insertAlertWithOrigin(t, ctx, d, "proc_creation_macos_applescript", "", `{"pid":21}`)
	ranAgain, err := d.BackfillAlertOrigins(ctx, coord, rules)
	require.NoError(t, err)
	assert.False(t, ranAgain, "the recorded completion answers without taking the lock")
	assert.Empty(t, originOfAlert(t, ctx, d, probe),
		"and without reading alerts: a pass that ran would have credited this row")
}

// spec:server-detection-rules-engine/alerts-from-vendored-rules-are-credited/a-pass-that-fails-is-retried
//
// TestBackfillAlertOrigins_AFailedPassIsRetried pins the ordering that makes durable completion safe: the marker follows a
// successful pass rather than accompanying it. Getting this backwards would turn one transient error into a permanently unmet
// licence obligation, with nothing to notice it, because no later start would look at those rows again.
//
// The failure is injected through the origin column's own width rather than by breaking the schema, so what fails is the pass's
// own UPDATE, which is the shape a real failure takes.
func TestBackfillAlertOrigins_AFailedPassIsRetried(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	coord := soleLeader{}

	id := insertAlertWithOrigin(t, ctx, d, "proc_creation_macos_applescript", "", `{"pid":30}`)

	tooLong := strings.Repeat("A", 300)
	_, err := d.BackfillAlertOrigins(ctx, coord, []rulesapi.Rule{
		stubOriginRule{id: "proc_creation_macos_applescript", origin: tooLong},
	})
	require.Error(t, err, "an origin wider than the column fails the pass")
	require.Empty(t, originOfAlert(t, ctx, d, id))

	ran, err := d.BackfillAlertOrigins(ctx, coord, []rulesapi.Rule{
		stubOriginRule{id: "proc_creation_macos_applescript", origin: "SigmaHQ"},
	})
	require.NoError(t, err)
	assert.True(t, ran, "nothing was recorded, so the next start runs the pass")
	assert.Equal(t, "SigmaHQ", originOfAlert(t, ctx, d, id), "and credits the rows the failed pass did not")
}

// spec:server-detection-rules-engine/alerts-from-vendored-rules-are-credited/a-pass-that-fails-is-retried
//
// TestBackfillAlertOrigins_APassThatStopsPartwayIsRetried is the case the failing test above cannot reach: a pass that credited
// SOME rows and then stopped. That is the shape a shutdown produces, and it is the one where recording completion too early would
// be silently destructive, because the rows already credited make the outcome look like a success.
//
// Deterministic rather than timed, which is the reason it is built this way. Cancelling a context mid-walk would race the batch
// loop, and a race that loses does not fail the test, it completes the pass and records the marker. Instead the failure is placed
// in the SECOND batch by id: a full batch of rows for a rule whose origin fits, then one row, at a higher id, for a rule whose
// origin does not. The walk is by primary key, so the first batch commits and the second cannot.
func TestBackfillAlertOrigins_APassThatStopsPartwayIsRetried(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})

	const firstRule = "proc_creation_macos_applescript"
	const secondRule = "proc_creation_macos_base64_decode"
	// One full batch. Mirrors mysql.backfillBatchSize, which is unexported; TestBackfillAlertOrigins_CreditsMoreThanOneBatch
	// hardcodes the same number for the same reason. If that constant moves, this test stops being a partial pass and the
	// require below says so rather than passing quietly.
	const oneBatch = 1000
	values := make([]string, 0, oneBatch)
	args := make([]any, 0, oneBatch*2)
	for i := range oneBatch {
		values = append(values, "(?, '"+firstRule+"', 'detection', 'high', 'seeded', 'seeded', '', ?, '[]')")
		args = append(args, "host-partway", fmt.Sprintf(`{"pid":%d}`, i))
	}
	_, err := d.Store().DB().ExecContext(ctx,
		`INSERT INTO alerts (host_id, rule_id, source, severity, title, description, origin, subject, techniques) VALUES `+
			strings.Join(values, ", "), args...)
	require.NoError(t, err)
	// Inserted after the batch, so it carries a higher id and lands in the second pass of the walk.
	last := insertAlertWithOrigin(t, ctx, d, secondRule, "", `{"pid":999999}`)

	_, err = d.BackfillAlertOrigins(ctx, soleLeader{}, []rulesapi.Rule{
		stubOriginRule{id: firstRule, origin: "SigmaHQ"},
		stubOriginRule{id: secondRule, origin: strings.Repeat("A", 300)},
	})
	require.Error(t, err, "the second batch cannot be written")

	var credited int
	require.NoError(t, d.Store().DB().GetContext(ctx, &credited,
		`SELECT COUNT(*) FROM alerts WHERE host_id = 'host-partway' AND origin = 'SigmaHQ'`))
	require.Equal(t, oneBatch, credited, "the first batch did commit, which is what makes this a PARTIAL pass")
	require.Empty(t, originOfAlert(t, ctx, d, last))

	ran, err := d.BackfillAlertOrigins(ctx, soleLeader{}, []rulesapi.Rule{
		stubOriginRule{id: firstRule, origin: "SigmaHQ"},
		stubOriginRule{id: secondRule, origin: "SigmaHQ"},
	})
	require.NoError(t, err)
	assert.True(t, ran, "a partial pass recorded nothing, so the next start runs")
	assert.Equal(t, "SigmaHQ", originOfAlert(t, ctx, d, last), "and finishes the row the interrupted one never reached")
}

// spec:server-detection-rules-engine/alerts-from-vendored-rules-are-credited/a-pass-that-fails-is-retried
//
// TestBackfillAlertOrigins_AStartCutShortBeforeThePassIsRetried covers the earlier half of a shutdown: the process is already
// going down when the start-up work is reached, so nothing runs at all. It is the cheap end of the same ordering, and it is here
// because the completion LOOKUP is the first thing that touches the database, so it is the first thing a cancelled context stops.
func TestBackfillAlertOrigins_AStartCutShortBeforeThePassIsRetried(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	rules := []rulesapi.Rule{stubOriginRule{id: "proc_creation_macos_applescript", origin: "SigmaHQ"}}

	id := insertAlertWithOrigin(t, t.Context(), d, "proc_creation_macos_applescript", "", `{"pid":40}`)

	stopped, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := d.BackfillAlertOrigins(stopped, soleLeader{}, rules)
	require.Error(t, err)

	ran, err := d.BackfillAlertOrigins(t.Context(), soleLeader{}, rules)
	require.NoError(t, err)
	assert.True(t, ran, "a start that was cut short recorded nothing, so the next one runs")
	assert.Equal(t, "SigmaHQ", originOfAlert(t, t.Context(), d, id))
}

// leaderAfterAPeer runs a hook before the callback, standing in for the replica that finished the pass and released the lock
// while this one was waiting for it. It is the only way to reach that window from a test: the two replicas of a rolling restart
// start in sequence, so the interesting case is not two callbacks overlapping but one starting after the other has finished.
type leaderAfterAPeer struct {
	leader.Coordinator
	peerFinished func()
}

func (c leaderAfterAPeer) DoOnceIfLeader(ctx context.Context, _ string, fn func(context.Context) error) (bool, error) {
	c.peerFinished()
	return true, fn(ctx)
}

// TestBackfillAlertOrigins_APeerFinishingFirstIsNotRepeated covers the check INSIDE the lock, which the check outside it cannot
// stand in for. Both replicas read "not done" before either has run, so the outer check waves both through; only the one that
// takes the lock second can still see the peer's record, and only if it looks again.
//
// Without the second look this is a wasted scan rather than a wrong answer, which is exactly why it needs a test: nothing about
// the alerts would be incorrect afterwards, so the cost is invisible in every other assertion here.
func TestBackfillAlertOrigins_APeerFinishingFirstIsNotRepeated(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})

	id := insertAlertWithOrigin(t, ctx, d, "proc_creation_macos_applescript", "", `{"pid":50}`)
	coord := leaderAfterAPeer{peerFinished: func() {
		require.NoError(t, d.Store().MarkBackfillCompleted(ctx, "alert_origins"))
	}}

	ran, err := d.BackfillAlertOrigins(ctx, coord, []rulesapi.Rule{
		stubOriginRule{id: "proc_creation_macos_applescript", origin: "SigmaHQ"},
	})
	require.NoError(t, err)
	assert.True(t, ran, "this replica did hold the lock, which is what DoOnceIfLeader reports")
	assert.Empty(t, originOfAlert(t, ctx, d, id),
		"but it must look again once it has the lock, and skip the pass a peer already completed")
}

// TestMarkBackfillCompleted_IsIdempotent covers two replicas that both somehow ran the pass, which the leader lock makes unlikely
// rather than impossible. The second writer must agree with the first rather than error on a duplicate key, because a pass that
// did its work and then failed to say so would be repeated forever.
func TestMarkBackfillCompleted_IsIdempotent(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})

	done, err := d.Store().BackfillCompleted(ctx, "alert_origins")
	require.NoError(t, err)
	require.False(t, done, "nothing has run yet")

	require.NoError(t, d.Store().MarkBackfillCompleted(ctx, "alert_origins"))
	require.NoError(t, d.Store().MarkBackfillCompleted(ctx, "alert_origins"))

	done, err = d.Store().BackfillCompleted(ctx, "alert_origins")
	require.NoError(t, err)
	assert.True(t, done)

	other, err := d.Store().BackfillCompleted(ctx, "something_else")
	require.NoError(t, err)
	assert.False(t, other, "completion is per backfill, not a single flag for all of them")
}

// plainRule declares no origin, so OriginOf reports this project and the scope decision skips it.
type plainRule struct{ id string }

func (r plainRule) ID() string           { return r.id }
func (r plainRule) DisplayName() string  { return r.id }
func (r plainRule) Techniques() []string { return nil }
func (r plainRule) Platforms() []rulesapi.Platform {
	return []rulesapi.Platform{rulesapi.PlatformDarwin}
}
func (r plainRule) Doc() rulesapi.Documentation {
	return rulesapi.Documentation{Title: r.id, EventTypes: []string{"exec"}}
}
func (r plainRule) SupportedExclusionMatchTypes() []rulesapi.ExclusionMatchType { return nil }
func (r plainRule) Evaluate(context.Context, []rulesapi.Event, rulesapi.GraphReader) ([]rulesapi.Finding, error) {
	return nil, nil
}

// TestBackfillAlertOrigins_NoVendoredRulesSkipsTheLock covers the deployment running none: it must not take a server-global
// lock to discover it has nothing to do, since every replica would queue on it at every boot for no work.
func TestBackfillAlertOrigins_NoVendoredRulesSkipsTheLock(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	coord := leader.NewMySQL(d.Store().DB(), slog.New(slog.DiscardHandler))

	ran, err := d.BackfillAlertOrigins(ctx, coord, []rulesapi.Rule{plainRule{id: "suspicious_exec"}})
	require.NoError(t, err)
	assert.False(t, ran, "nothing in scope means no lock and no pass")
}

// TestBackfillAlertOrigins_NoCoordinatorIsANoOp covers a deployment wired without leader election, where taking the pass would
// mean every replica running it concurrently.
func TestBackfillAlertOrigins_NoCoordinatorIsANoOp(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ran, err := d.BackfillAlertOrigins(t.Context(), nil, []rulesapi.Rule{
		stubOriginRule{id: "proc_creation_macos_applescript", origin: "SigmaHQ"},
	})
	require.NoError(t, err)
	assert.False(t, ran)
}

// spec:server-detection-rules-engine/alerts-from-vendored-rules-are-credited/more-alerts-than-one-batch-are-all-credited
//
// TestBackfillAlertOrigins_CreditsMoreThanOneBatch exercises the loop, which exists because the statement cannot use an index:
// alerts has none on origin, and rule_id sits third in the dedup key, so one unbounded UPDATE would hold row locks across a table
// scan at boot. The batch bound is what keeps that from happening, and a bound is only correct if the loop around it terminates
// having done all the work.
//
// Seeds one more row than a batch holds, which is the smallest input that proves a second pass happens at all.
//
// What this does NOT prove is the id cursor, and that is a property of the cursor rather than a gap here. Each batch's UPDATE
// removes its rows from the `origin = ”` predicate, so the loop terminates having credited everything whether or not the next
// pass resumes from the last id. The cursor's whole effect is that the table is scanned once rather than once per batch, which
// is not observable from a functional assertion. See the coverage note on backfillBatchSize.
func TestBackfillAlertOrigins_CreditsMoreThanOneBatch(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})

	const rows = 1001
	values := make([]string, 0, rows)
	args := make([]any, 0, rows*2)
	for i := range rows {
		values = append(values, "(?, 'proc_creation_macos_applescript', 'detection', 'high', 'seeded', 'seeded', '', ?, '[]')")
		args = append(args, "host-batch", fmt.Sprintf(`{"pid":%d}`, i))
	}
	_, err := d.Store().DB().ExecContext(ctx,
		`INSERT INTO alerts (host_id, rule_id, source, severity, title, description, origin, subject, techniques) VALUES `+
			strings.Join(values, ", "), args...)
	require.NoError(t, err)

	updated, err := d.Store().BackfillAlertOrigins(ctx, map[string]string{
		"proc_creation_macos_applescript": "SigmaHQ",
	})
	require.NoError(t, err)
	assert.Equal(t, int64(rows), updated, "every row is credited, across however many batches that takes")

	var uncredited int
	require.NoError(t, d.Store().DB().GetContext(ctx, &uncredited,
		`SELECT COUNT(*) FROM alerts WHERE host_id = 'host-batch' AND origin = ''`))
	assert.Zero(t, uncredited, "the loop must not stop at the first batch")
}
