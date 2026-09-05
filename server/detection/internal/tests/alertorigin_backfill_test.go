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

	// Running again is the second boot, and must change nothing.
	ranAgain, err := d.BackfillAlertOrigins(ctx, coord, []rulesapi.Rule{
		stubOriginRule{id: "proc_creation_macos_applescript", origin: "SigmaHQ"},
	})
	require.NoError(t, err)
	assert.True(t, ranAgain, "the lock is free again, so this replica runs the pass")
	assert.Equal(t, "SigmaHQ", originOfAlert(t, ctx, d, vendored))
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
