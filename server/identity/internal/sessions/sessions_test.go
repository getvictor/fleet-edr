package sessions_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/internal/sessions"
	"github.com/fleetdm/edr/server/identity/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

// newTestStore opens a fresh DB and pre-inserts a stub users row whose id is the
// userID tests reference (1, 2, 7, 42 — whatever the test passes to Create). Without
// this the FK constraint sessions.user_id → users(id) rejects inserts.
func newTestStore(t *testing.T, opts sessions.Options) *sessions.Store {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	for _, uid := range []int64{1, 2, 7, 42} {
		_, err := db.ExecContext(t.Context(),
			`INSERT INTO users (id, email, password_hash, password_salt) VALUES (?, ?, ?, ?)`,
			uid, "u"+intToStr(uid)+"@test", []byte("stub-hash"), []byte("stub-salt"))
		if err != nil {
			t.Fatalf("seed test user %d: %v", uid, err)
		}
	}
	return sessions.New(db, opts)
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
	s := newTestStore(t, sessions.Options{})
	ctx := t.Context()

	sess, err := s.Create(ctx, 42, sessions.CreateOptions{})
	require.NoError(t, err)
	assert.Len(t, sess.ID, sessions.IDLen)
	assert.Len(t, sess.CSRFToken, sessions.IDLen)
	assert.Equal(t, int64(42), sess.UserID)
	assert.False(t, sess.CreatedAt.IsZero())
	assert.True(t, sess.ExpiresAt.After(sess.CreatedAt))
}

func TestCreate_IDsAreUnique(t *testing.T) {
	s := newTestStore(t, sessions.Options{})
	ctx := t.Context()

	a, err := s.Create(ctx, 1, sessions.CreateOptions{})
	require.NoError(t, err)
	b, err := s.Create(ctx, 1, sessions.CreateOptions{})
	require.NoError(t, err)
	assert.False(t, bytes.Equal(a.ID, b.ID), "session ids must differ")
	assert.False(t, bytes.Equal(a.CSRFToken, b.CSRFToken), "csrf tokens must differ")
}

func TestGet_ActiveRoundTrip(t *testing.T) {
	s := newTestStore(t, sessions.Options{})
	ctx := t.Context()

	created, err := s.Create(ctx, 7, sessions.CreateOptions{})
	require.NoError(t, err)

	got, err := s.Get(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, got.ID)
	assert.Equal(t, int64(7), got.UserID)
	assert.Equal(t, created.CSRFToken, got.CSRFToken)
}

// Phase 4 added IdentityID + AuthMethod columns. Round-trip both
// through Create -> Get to pin the schema + scan path. A regression
// here would silently strip OIDC sessions of their identity link
// (breaking later admin queries that pivot on identities) or default
// every session to local_password (breaking authz rules that branch
// on auth_method).
func TestGet_IdentityIDAndAuthMethodRoundTrip(t *testing.T) {
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	for _, uid := range []int64{1, 7} {
		_, err := db.ExecContext(t.Context(),
			`INSERT INTO users (id, email, password_hash, password_salt) VALUES (?, ?, ?, ?)`,
			uid, "u"+intToStr(uid)+"@test", []byte("stub-hash"), []byte("stub-salt"))
		require.NoError(t, err)
	}
	const identityID int64 = 9001
	_, err := db.ExecContext(t.Context(),
		`INSERT INTO identities (id, user_id, provider, subject) VALUES (?, ?, ?, ?)`,
		identityID, int64(7), "oidc", "abc-subject")
	require.NoError(t, err, "seed identities row")

	s := sessions.New(db, sessions.Options{})
	ctx := t.Context()

	idCopy := identityID
	created, err := s.Create(ctx, 7, sessions.CreateOptions{
		IdentityID: &idCopy,
		AuthMethod: "oidc",
	})
	require.NoError(t, err)
	require.NotNil(t, created.IdentityID)
	assert.Equal(t, identityID, *created.IdentityID)
	assert.Equal(t, "oidc", created.AuthMethod)

	got, err := s.Get(ctx, created.ID)
	require.NoError(t, err)
	require.NotNil(t, got.IdentityID, "identity_id must round-trip")
	assert.Equal(t, identityID, *got.IdentityID)
	assert.Equal(t, "oidc", got.AuthMethod, "auth_method must round-trip")
}

func TestGet_WrongLengthReturnsNotFound(t *testing.T) {
	s := newTestStore(t, sessions.Options{})
	_, err := s.Get(t.Context(), []byte("short"))
	require.ErrorIs(t, err, sessions.ErrNotFound)
}

func TestGet_UnknownIDReturnsNotFound(t *testing.T) {
	s := newTestStore(t, sessions.Options{})
	_, err := s.Get(t.Context(), make([]byte, sessions.IDLen))
	require.ErrorIs(t, err, sessions.ErrNotFound)
}

func TestGet_ExpiredReturnsNotFound(t *testing.T) {
	// Drive the clock backwards so the row we just created is already past its
	// expires_at when Get runs. This is more reliable than time.Sleep(ttl+1) and
	// doesn't tie the test to wall-clock duration.
	start := time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC)
	nowFn, advance := frozenClock(start)
	s := newTestStore(t, sessions.Options{TTL: time.Hour, Now: nowFn})
	ctx := t.Context()

	created, err := s.Create(ctx, 1, sessions.CreateOptions{})
	require.NoError(t, err)

	advance(2 * time.Hour) // past the 1 hour TTL
	_, err = s.Get(ctx, created.ID)
	require.ErrorIs(t, err, sessions.ErrNotFound)
}

func TestDelete_IsIdempotent(t *testing.T) {
	s := newTestStore(t, sessions.Options{})
	ctx := t.Context()

	sess, err := s.Create(ctx, 1, sessions.CreateOptions{})
	require.NoError(t, err)
	require.NoError(t, s.Delete(ctx, sess.ID))
	require.NoError(t, s.Delete(ctx, sess.ID), "second delete of same id must not error")
	require.NoError(t, s.Delete(ctx, make([]byte, sessions.IDLen)), "delete of unknown id must not error")
}

func TestCleanupExpired_RemovesOnlyExpired(t *testing.T) {
	start := time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC)
	nowFn, advance := frozenClock(start)
	s := newTestStore(t, sessions.Options{TTL: time.Hour, Now: nowFn})
	ctx := t.Context()

	active, err := s.Create(ctx, 1, sessions.CreateOptions{})
	require.NoError(t, err)

	// Advance past TTL so the first row expires, then create a fresh row.
	advance(2 * time.Hour)
	stillActive, err := s.Create(ctx, 2, sessions.CreateOptions{})
	require.NoError(t, err)

	removed, err := s.CleanupExpired(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), removed)

	// The expired row is gone.
	_, err = s.Get(ctx, active.ID)
	require.ErrorIs(t, err, sessions.ErrNotFound)

	// The fresh row is still there.
	got, err := s.Get(ctx, stillActive.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), got.UserID)
}
