package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUpdateHostLastSeen_InsertsAndUpdates covers the two states of the Phase 4 host
// liveness upsert: first call for a never-seen host creates the row; subsequent calls
// for the same host bump the timestamp monotonically.
func TestUpdateHostLastSeen_InsertsAndUpdates(t *testing.T) {
	s := OpenTestStore(t)
	ctx := t.Context()

	start := time.Unix(1_700_000_000, 0).UTC()
	require.NoError(t, s.UpdateHostLastSeen(ctx, "host-a", start))

	var got int64
	require.NoError(t, s.db.GetContext(ctx, &got, `SELECT last_seen_ns FROM hosts WHERE host_id = ?`, "host-a"))
	assert.Equal(t, start.UnixNano(), got)

	// Second call with a later timestamp advances the row.
	later := start.Add(10 * time.Second)
	require.NoError(t, s.UpdateHostLastSeen(ctx, "host-a", later))
	require.NoError(t, s.db.GetContext(ctx, &got, `SELECT last_seen_ns FROM hosts WHERE host_id = ?`, "host-a"))
	assert.Equal(t, later.UnixNano(), got)
}

// TestUpdateHostLastSeen_MonotonicallyAdvances locks in the GREATEST guard: an older
// timestamp (e.g. clock skew on a backdated request) must not regress the row.
func TestUpdateHostLastSeen_MonotonicallyAdvances(t *testing.T) {
	s := OpenTestStore(t)
	ctx := t.Context()

	later := time.Unix(1_700_000_100, 0).UTC()
	older := time.Unix(1_700_000_000, 0).UTC()

	require.NoError(t, s.UpdateHostLastSeen(ctx, "host-a", later))
	require.NoError(t, s.UpdateHostLastSeen(ctx, "host-a", older))

	var got int64
	require.NoError(t, s.db.GetContext(ctx, &got, `SELECT last_seen_ns FROM hosts WHERE host_id = ?`, "host-a"))
	assert.Equal(t, later.UnixNano(), got, "clock-skewed older timestamp must not regress the row")
}
