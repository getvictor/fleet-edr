//go:build integration

package tests

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
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

func originOfAlert(t *testing.T, ctx context.Context, d *bootstrap.Detection, id int64) string {
	t.Helper()
	var origin string
	require.NoError(t, d.Store().DB().GetContext(ctx, &origin, `SELECT origin FROM alerts WHERE id = ?`, id))
	return origin
}

// spec:server-detection-rules-engine/alerts-raised-before-attribution-was-recorded-are-credited/an-uncredited-alert-from-a-vendored-rule-is-credited
// spec:server-detection-rules-engine/alerts-raised-before-attribution-was-recorded-are-credited/an-attribution-already-recorded-is-never-overwritten
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
	projection := insertAlertWithOrigin(t, ctx, d, "application_control_block", "", `{"pid":3}`)
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
		"a projection's alert must stay empty, or this project claims authorship of the operator's own policy entry")
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

var _ = api.Alert{}
