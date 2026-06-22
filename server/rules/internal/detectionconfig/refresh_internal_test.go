package detectionconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/migrations/runner"
	rulesmigrations "github.com/fleetdm/edr/server/rules/migrations"
	"github.com/fleetdm/edr/server/testdb"
)

// White-box tests for the refresh loop's error/cancellation branches, which the black-box RefreshLoop convergence test cannot drive
// deterministically (the select catches ctx.Done() between ticks, so an in-tick cancellation is unreachable from outside).

func newInternalStore(t *testing.T) (*Store, *sqlx.DB) {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, runner.Up(t.Context(), db, rulesmigrations.FS, runner.Options{
		Context:   "rules",
		TableName: "rules_goose_db_version",
	}))
	return NewStore(db), db
}

func TestHandleRefreshErr(t *testing.T) {
	t.Parallel()
	svc := NewService(NewStore(testdb.Open(t)), nil, nil, nil) // store is unused by handleRefreshErr; just satisfies the nil-store guard

	// Live context: the error is transient, so log + continue (stop=false).
	assert.False(t, svc.handleRefreshErr(context.Background(), "version poll", errors.New("boom")),
		"a transient error under a live context must not stop the loop")

	// Cancelled context: shutdown raced the poll, so stop silently (stop=true, no WARN).
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.True(t, svc.handleRefreshErr(ctx, "reload", context.Canceled),
		"a cancelled context must stop the loop")
}

func TestRefreshTick(t *testing.T) {
	t.Parallel()
	store, _ := newInternalStore(t)
	svc := NewService(store, nil, nil, nil)
	require.NoError(t, svc.Reload(t.Context()))

	// Stored version matches the loaded snapshot: nothing to do, keep looping.
	assert.False(t, svc.refreshTick(t.Context()), "an unchanged version must not stop the loop")

	// Cancelled context makes store.Version(ctx) return a cancellation error, so the tick stops the loop.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.True(t, svc.refreshTick(ctx), "a cancelled context during the poll must stop the loop")
}
