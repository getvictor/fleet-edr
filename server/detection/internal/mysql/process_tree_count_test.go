package mysql_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	"github.com/fleetdm/edr/server/detection/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

// newStoreAndDB is newTestStore plus the handle underneath it, for the tests that seed rows faster than the ingest path can.
func newStoreAndDB(tb testing.TB) (*mysql.Store, *sqlx.DB) {
	tb.Helper()
	db := testdb.Open(tb)
	require.NoError(tb, testkit.ApplySchema(tb.Context(), db))
	s, err := mysql.New(db, testkit.NewMemArchive(), nil)
	require.NoError(tb, err)
	return s, db
}

// seedProcesses bulk-inserts n minimal process rows for one host, all forked at forkTimeNs and none exited.
//
// One multi-row INSERT rather than a loop through the ingest path: the bound under test only shows itself past 10,000 rows, and
// materialising those from fork events would cost minutes to prove something about one SQL statement.
func seedProcesses(tb testing.TB, ctx context.Context, db *sqlx.DB, hostID string, n int, forkTimeNs int64) {
	tb.Helper()
	var b strings.Builder
	b.WriteString("INSERT INTO processes (host_id, pid, ppid, path, fork_time_ns) VALUES ")
	args := make([]any, 0, n*3)
	for i := range n {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString("(?, ?, 1, '/bin/seeded', ?)")
		args = append(args, hostID, i+1, forkTimeNs)
	}
	_, err := db.ExecContext(ctx, b.String(), args...)
	require.NoError(tb, err, "bulk seed must succeed or the assertions below prove nothing")
}

// spec:server-rest-api/per-host-process-forest/counting-stops-at-its-bound-rather-than-scanning-the-whole-window
//
// TestCountProcessTree_StopsAtItsBound pins the bound against a real database, which is the only place it can be pinned: the whole
// point is what the SQL does when the window matches more rows than the bound, and a fake store can only echo a number the test
// already chose.
//
// This replaced an unbounded COUNT that took the endpoint down. On a dogfood host carrying 5.2M process rows, a 24-hour window
// matched 542,268 of them and the count ran past 120 seconds against a 30-second write timeout, so the request returned 500 and the
// operator's process graph rendered as an error.
func TestCountProcessTree_StopsAtItsBound(t *testing.T) {
	t.Parallel()
	store, db := newStoreAndDB(t)
	ctx := t.Context()

	const host = "count-bound-host"
	const forkTime = int64(1000)
	// One row past the bound: enough to exercise it without paying for rows the assertions do not need.
	seeded := mysql.ProcessTreeCountBound + 1
	seedProcesses(t, ctx, db, host, seeded, forkTime)

	got, capped, err := store.CountProcessTree(ctx, host, api.TimeRange{FromNs: 0, ToNs: forkTime + 1})
	require.NoError(t, err)

	assert.Equal(t, int64(mysql.ProcessTreeCountBound), got,
		"counting MUST stop at the bound rather than return the true total, which is what made this read unbounded")
	assert.True(t, capped, "a count that stopped at its bound MUST say so, or a client reads the ceiling as a real total")
	assert.Less(t, got, int64(seeded), "the seed must exceed the bound or this test is vacuous")
}

// A window inside the bound still reports its exact total and does not claim to have been capped. This is the case the bound must
// NOT disturb: almost every real read is nowhere near 10,000 rows, and those still get a real denominator.
func TestCountProcessTree_ExactBelowTheBound(t *testing.T) {
	t.Parallel()
	store, db := newStoreAndDB(t)
	ctx := t.Context()

	const host = "count-exact-host"
	const forkTime = int64(1000)
	const seeded = 12
	seedProcesses(t, ctx, db, host, seeded, forkTime)

	got, capped, err := store.CountProcessTree(ctx, host, api.TimeRange{FromNs: 0, ToNs: forkTime + 1})
	require.NoError(t, err)
	assert.Equal(t, int64(seeded), got, "below the bound the count is exact")
	assert.False(t, capped, "below the bound nothing was capped, and saying otherwise would hide a real total behind a floor")
}

// spec:server-rest-api/per-host-process-forest/counting-stops-at-its-bound-rather-than-scanning-the-whole-window
//
// The boundary Copilot caught on review: with EXACTLY ProcessTreeCountBound matching rows the old predicate (`total >= bound`)
// reported capped, and the page then read "more than 10,000" over a window holding precisely 10,000. The count now probes one row
// past the bound so "capped" means strictly more matched, and clamps the reported number back to the bound.
func TestCountProcessTree_ExactlyAtTheBoundIsNotCapped(t *testing.T) {
	t.Parallel()
	store, db := newStoreAndDB(t)
	ctx := t.Context()

	const host = "count-at-bound-host"
	const forkTime = int64(1000)
	seedProcesses(t, ctx, db, host, mysql.ProcessTreeCountBound, forkTime)

	got, capped, err := store.CountProcessTree(ctx, host, api.TimeRange{FromNs: 0, ToNs: forkTime + 1})
	require.NoError(t, err)
	assert.Equal(t, int64(mysql.ProcessTreeCountBound), got, "the total is exactly the bound and is reported as itself")
	assert.False(t, capped,
		"nothing lies beyond the bound here, so claiming a floor would put \"more than 10,000\" on a window holding 10,000")
}
