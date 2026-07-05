package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/testdb/full"
)

// TestMaybeRefreshExisting covers the idempotent re-run dispatcher's branches: the --force short-circuit, the not-yet-seeded
// "proceed with a fresh replay" report, the already-seeded refresh-in-place report, and the wrapped already-seeded-check error.
func TestMaybeRefreshExisting(t *testing.T) {
	t.Parallel()

	t.Run("force short-circuits to a full re-seed", func(t *testing.T) {
		t.Parallel()
		db := full.Open(t)
		s := newSeeder(config{force: true}, db, testHTTPClient(), discardLogger())
		handled, err := s.maybeRefreshExisting(t.Context())
		require.NoError(t, err)
		assert.False(t, handled, "force=true means run() proceeds to a full replay, not a refresh")
	})

	t.Run("not-yet-seeded reports handled=false", func(t *testing.T) {
		t.Parallel()
		db := full.Open(t)
		s := newSeeder(config{}, db, testHTTPClient(), discardLogger())
		handled, err := s.maybeRefreshExisting(t.Context())
		require.NoError(t, err)
		assert.False(t, handled, "an empty DB is not seeded, so a fresh replay must proceed")
	})

	t.Run("already-seeded refreshes in place and reports handled=true", func(t *testing.T) {
		t.Parallel()
		db := full.Open(t)
		// The keychain marker on a demo host makes alreadySeeded true; with no replayed process rows the refresh is a no-op, but
		// maybeRefreshExisting must still report handled=true so run() skips the replay.
		insertAlert(t, db, firstDemoHostID(t), keychainRuleID, "detection", "high")
		s := newSeeder(config{}, db, testHTTPClient(), discardLogger())
		handled, err := s.maybeRefreshExisting(t.Context())
		require.NoError(t, err)
		assert.True(t, handled)
	})

	t.Run("already-seeded check error is wrapped", func(t *testing.T) {
		t.Parallel()
		db := full.Open(t)
		require.NoError(t, db.Close()) // a closed handle makes every query fail, exercising the error branch
		s := newSeeder(config{}, db, testHTTPClient(), discardLogger())
		_, err := s.maybeRefreshExisting(t.Context())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "check already-seeded")
	})
}

// TestRefreshTimestampsAlreadyRecent covers the deltaSec <= 0 skip: when the newest replayed row is already at (or newer than) the
// target recent window, refreshTimestamps must NOT slide anything backward.
func TestRefreshTimestampsAlreadyRecent(t *testing.T) {
	t.Parallel()
	db := full.Open(t)
	ctx := t.Context()
	s := newSeeder(config{}, db, testHTTPClient(), discardLogger())
	hostID := firstDemoHostID(t)

	nowNs := time.Now().UnixNano()
	_, err := db.ExecContext(ctx,
		`INSERT INTO processes (host_id, pid, ppid, path, fork_time_ns, last_seen_ns) VALUES (?, ?, 1, '/bin/recent', ?, ?)`,
		hostID, 700, nowNs, nowNs)
	require.NoError(t, err)

	require.NoError(t, s.refreshTimestamps(ctx))

	var fork int64
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT fork_time_ns FROM processes WHERE host_id = ? AND pid = 700`, hostID).Scan(&fork))
	assert.Equal(t, nowNs, fork, "an already-recent demo must not be slid backward (deltaSec <= 0 is a no-op)")
}

// TestRefreshTimestampsDBErrors covers the DB-error branches of the refresh path via a closed handle (a legitimate fault injector
// that touches no production code): the newest-timestamp read error propagates from refreshTimestamps, and applyTimestampSlide's
// begin-transaction failure is wrapped.
func TestRefreshTimestampsDBErrors(t *testing.T) {
	t.Parallel()

	t.Run("newest-timestamp read error propagates", func(t *testing.T) {
		t.Parallel()
		db := full.Open(t)
		require.NoError(t, db.Close())
		s := newSeeder(config{}, db, testHTTPClient(), discardLogger())
		err := s.refreshTimestamps(t.Context())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "read newest demo timestamp")
	})

	t.Run("applyTimestampSlide begin-tx error is wrapped", func(t *testing.T) {
		t.Parallel()
		db := full.Open(t)
		require.NoError(t, db.Close())
		s := newSeeder(config{}, db, testHTTPClient(), discardLogger())
		inClause, hostArgs, err := demoHostScope()
		require.NoError(t, err)
		err = s.applyTimestampSlide(t.Context(), inClause, hostArgs, 1000, 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "begin refresh tx")
	})
}
