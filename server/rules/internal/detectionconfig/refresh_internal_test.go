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
	cases := []struct {
		name     string
		cancel   bool // cancel the context before the call
		wantStop bool
	}{
		{"live context logs and continues", false, false},
		{"cancelled context stops silently", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			if tc.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			assert.Equal(t, tc.wantStop, svc.handleRefreshErr(ctx, "version poll", errors.New("boom")))
		})
	}
}

func TestRefreshTick(t *testing.T) {
	t.Parallel()
	store, _ := newInternalStore(t)
	svc := NewService(store, nil, nil, nil)
	require.NoError(t, svc.Reload(t.Context()))
	cases := []struct {
		name     string
		cancel   bool // cancel the context, making store.Version(ctx) return a cancellation error
		wantStop bool
	}{
		{"unchanged version keeps looping", false, false},
		{"cancelled context during poll stops", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			if tc.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(context.Background())
				cancel()
			}
			assert.Equal(t, tc.wantStop, svc.refreshTick(ctx))
		})
	}
}
