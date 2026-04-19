package sessions

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/store"
)

// newTestStore opens a fresh DB and pre-inserts a stub users row whose id is the
// userID tests reference (1, 2, 7, 42 — whatever the test passes to Create). Without
// this the Phase 3 FK constraint sessions.user_id → users(id) rejects inserts.
func newTestStore(t *testing.T, opts Options) *Store {
	t.Helper()
	s := store.OpenTestStore(t)
	for _, uid := range []int64{1, 2, 7, 42} {
		_, err := s.DB().ExecContext(t.Context(),
			`INSERT INTO users (id, email, password_hash, password_salt) VALUES (?, ?, ?, ?)`,
			uid, "u"+intToStr(uid)+"@test", []byte("stub-hash"), []byte("stub-salt"))
		if err != nil {
			t.Fatalf("seed test user %d: %v", uid, err)
		}
	}
	return New(s.DB(), opts)
}

func intToStr(i int64) string {
	// Tiny stdlib-free int→string to keep the test helper dependency-light.
	if i == 0 {
		return "0"
	}
	const digits = "0123456789"
	var out []byte
	for i > 0 {
		out = append([]byte{digits[i%10]}, out...)
		i /= 10
	}
	return string(out)
}

// frozenClock returns a controllable time.Now for deterministic expiry tests. Starts at
// a fixed instant so changing the machine wall clock doesn't perturb assertions.
func frozenClock(start time.Time) (now func() time.Time, advance func(time.Duration)) {
	cur := start
	return func() time.Time { return cur }, func(d time.Duration) { cur = cur.Add(d) }
}

func TestCreate_ReturnsNewRow(t *testing.T) {
	s := newTestStore(t, Options{})
	ctx := t.Context()

	sess, err := s.Create(ctx, 42)
	require.NoError(t, err)
	assert.Len(t, sess.ID, IDLen)
	assert.Len(t, sess.CSRFToken, IDLen)
	assert.Equal(t, int64(42), sess.UserID)
	assert.False(t, sess.CreatedAt.IsZero())
	assert.True(t, sess.ExpiresAt.After(sess.CreatedAt))
}

func TestCreate_IDsAreUnique(t *testing.T) {
	s := newTestStore(t, Options{})
	ctx := t.Context()

	a, err := s.Create(ctx, 1)
	require.NoError(t, err)
	b, err := s.Create(ctx, 1)
	require.NoError(t, err)
	assert.False(t, bytes.Equal(a.ID, b.ID), "session ids must differ")
	assert.False(t, bytes.Equal(a.CSRFToken, b.CSRFToken), "csrf tokens must differ")
}

func TestGet_ActiveRoundTrip(t *testing.T) {
	s := newTestStore(t, Options{})
	ctx := t.Context()

	created, err := s.Create(ctx, 7)
	require.NoError(t, err)

	got, err := s.Get(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, got.ID)
	assert.Equal(t, int64(7), got.UserID)
	assert.Equal(t, created.CSRFToken, got.CSRFToken)
}

func TestGet_WrongLengthReturnsNotFound(t *testing.T) {
	s := newTestStore(t, Options{})
	_, err := s.Get(t.Context(), []byte("short"))
	require.ErrorIs(t, err, ErrNotFound)
}

func TestGet_UnknownIDReturnsNotFound(t *testing.T) {
	s := newTestStore(t, Options{})
	_, err := s.Get(t.Context(), make([]byte, IDLen))
	require.ErrorIs(t, err, ErrNotFound)
}

func TestGet_ExpiredReturnsNotFound(t *testing.T) {
	// Drive the clock backwards so the row we just created is already past its
	// expires_at when Get runs. This is more reliable than time.Sleep(ttl+1) and
	// doesn't tie the test to wall-clock duration.
	start := time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC)
	nowFn, advance := frozenClock(start)
	s := newTestStore(t, Options{TTL: time.Hour, Now: nowFn})
	ctx := t.Context()

	created, err := s.Create(ctx, 1)
	require.NoError(t, err)

	advance(2 * time.Hour) // past the 1 hour TTL
	_, err = s.Get(ctx, created.ID)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestDelete_IsIdempotent(t *testing.T) {
	s := newTestStore(t, Options{})
	ctx := t.Context()

	sess, err := s.Create(ctx, 1)
	require.NoError(t, err)
	require.NoError(t, s.Delete(ctx, sess.ID))
	require.NoError(t, s.Delete(ctx, sess.ID), "second delete of same id must not error")
	require.NoError(t, s.Delete(ctx, make([]byte, IDLen)), "delete of unknown id must not error")
}

func TestCleanupExpired_RemovesOnlyExpired(t *testing.T) {
	start := time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC)
	nowFn, advance := frozenClock(start)
	s := newTestStore(t, Options{TTL: time.Hour, Now: nowFn})
	ctx := t.Context()

	active, err := s.Create(ctx, 1)
	require.NoError(t, err)

	// Advance past TTL so the first row expires, then create a fresh row.
	advance(2 * time.Hour)
	stillActive, err := s.Create(ctx, 2)
	require.NoError(t, err)

	removed, err := s.CleanupExpired(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), removed)

	// The expired row is gone.
	_, err = s.Get(ctx, active.ID)
	require.ErrorIs(t, err, ErrNotFound)

	// The fresh row is still there.
	got, err := s.Get(ctx, stillActive.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), got.UserID)
}
