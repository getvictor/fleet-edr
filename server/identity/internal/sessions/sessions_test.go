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

// newTestStore opens a fresh DB and pre-inserts a stub users row whose id is the userID tests reference (1, 2, 7, 42 — whatever the
// test passes to Create). Without this the FK constraint sessions.user_id → users(id) rejects inserts.
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

// Phase 4 added IdentityID + AuthMethod columns. Round-trip both through Create -> Get to pin the schema + scan path. A regression
// here would silently strip OIDC sessions of their identity link (breaking later admin queries that pivot on identities) or default
// every session to local_password (breaking authz rules that branch on auth_method).
func TestGet_IdentityIDAndAuthMethodRoundTrip(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	s := newTestStore(t, sessions.Options{})
	_, err := s.Get(t.Context(), []byte("short"))
	require.ErrorIs(t, err, sessions.ErrNotFound)
}

func TestGet_UnknownIDReturnsNotFound(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, sessions.Options{})
	_, err := s.Get(t.Context(), make([]byte, sessions.IDLen))
	require.ErrorIs(t, err, sessions.ErrNotFound)
}

// spec:ui-authentication-session/sessions-expire-12-hours-after-issue/a-request-after-the-12-hour-window-is-rejected
//
// Pins the expired-session-rejection clause: a session whose absolute cap has elapsed returns
// ErrNotFound from Get, which the Session middleware translates into 401 on the wire (covered by
// TestSession_MissingCookieReturns401's same response shape). The spec scenario speaks of a flat 12h
// window; the impl uses configurable Idle + Absolute timeouts per session class (see
// sessions.Timeouts in sessions.go). This test uses a 1h cap for speed; the load-bearing contract
// the spec asserts is "after expiry the request is rejected," which is what the ErrNotFound below
// pins. The flat-12h-vs-configurable-timeouts difference is the spec/impl drift tracked in #257.
func TestGet_ExpiredReturnsNotFound(t *testing.T) {
	t.Parallel()
	// Drive the clock backwards so the row we just created is already past its expires_at when Get runs. This is more reliable than
	// time.Sleep(ttl+1) and doesn't tie the test to wall-clock duration.
	start := time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC)
	nowFn, advance := frozenClock(start)
	s := newTestStore(t, sessions.Options{
		Normal: sessions.Timeouts{Idle: time.Hour, Absolute: time.Hour},
		Now:    nowFn,
	})
	ctx := t.Context()

	created, err := s.Create(ctx, 1, sessions.CreateOptions{})
	require.NoError(t, err)

	advance(2 * time.Hour) // past the 1 hour absolute cap
	_, err = s.Get(ctx, created.ID)
	require.ErrorIs(t, err, sessions.ErrNotFound)
}

// TestGet_IdleExpiryReturnsNotFound covers the idle-cap branch: created recently (so absolute hasn't elapsed) but last_seen_at hasn't
// been touched in longer than Idle. Real-world shape: operator opens a tab, walks away without interacting for the idle window.
func TestGet_IdleExpiryReturnsNotFound(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC)
	nowFn, advance := frozenClock(start)
	s := newTestStore(t, sessions.Options{
		Normal: sessions.Timeouts{Idle: 30 * time.Minute, Absolute: 24 * time.Hour},
		Now:    nowFn,
	})
	ctx := t.Context()

	created, err := s.Create(ctx, 1, sessions.CreateOptions{AuthMethod: "oidc"})
	require.NoError(t, err)

	advance(31 * time.Minute) // past idle, well within absolute
	_, err = s.Get(ctx, created.ID)
	require.ErrorIs(t, err, sessions.ErrNotFound)
}

// TestGet_BreakglassUsesStrictTimeouts pins the per-class behaviour: a session minted with auth_method="local_password" expires under
// the break-glass pair, not the normal pair. The Idle here would be inside the break-glass cap if normal applied; under break-glass
// it's past.
func TestGet_BreakglassUsesStrictTimeouts(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC)
	nowFn, advance := frozenClock(start)
	s := newTestStore(t, sessions.Options{
		Normal:     sessions.Timeouts{Idle: 8 * time.Hour, Absolute: 24 * time.Hour},
		Breakglass: sessions.Timeouts{Idle: 15 * time.Minute, Absolute: 1 * time.Hour},
		Now:        nowFn,
	})
	ctx := t.Context()

	created, err := s.Create(ctx, 1, sessions.CreateOptions{AuthMethod: "local_password"})
	require.NoError(t, err)

	advance(20 * time.Minute) // past break-glass idle (15m), well inside normal idle (8h)
	_, err = s.Get(ctx, created.ID)
	require.ErrorIs(t, err, sessions.ErrNotFound, "break-glass session must enforce the strict pair")
}

// TestTouch_SlidingExtensionWithinAbsoluteCap proves the user-visible behaviour: a continuously-active session stays alive past the
// idle window because each Touch advances last_seen_at. The absolute cap still wins.
func TestTouch_SlidingExtensionWithinAbsoluteCap(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC)
	nowFn, advance := frozenClock(start)
	s := newTestStore(t, sessions.Options{
		Normal: sessions.Timeouts{Idle: 30 * time.Minute, Absolute: 2 * time.Hour},
		Now:    nowFn,
	})
	ctx := t.Context()

	created, err := s.Create(ctx, 1, sessions.CreateOptions{AuthMethod: "oidc"})
	require.NoError(t, err)
	cached := created.LastSeenAt

	// Three iterations of "20 min activity then a Touch" — total 60 min of
	// continuous activity past what would otherwise be a 30-min idle expiry.
	for range 3 {
		advance(20 * time.Minute)
		newSeen, err := s.Touch(ctx, created.ID, cached)
		require.NoError(t, err)
		assert.True(t, newSeen.After(cached), "touch must advance last_seen_at past throttle")
		cached = newSeen
	}

	// Session is still alive 60min after creation despite a 30min idle window.
	got, err := s.Get(ctx, created.ID)
	require.NoError(t, err)
	assert.WithinDuration(t, nowFn(), got.LastSeenAt, time.Second)

	// Push past the absolute cap (2h). Touch can't save it.
	advance(2 * time.Hour)
	_, _ = s.Touch(ctx, created.ID, cached)
	_, err = s.Get(ctx, created.ID)
	require.ErrorIs(t, err, sessions.ErrNotFound, "absolute cap wins over sliding extension")
}

// TestTouch_ThrottleSkipsRecentWrites verifies the per-session write-rate cap: a Touch within the throttle window is a no-op. Without
// this the middleware would write last_seen_at on every authenticated request, turning a busy session into a high-rate write.
func TestTouch_ThrottleSkipsRecentWrites(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC)
	nowFn, advance := frozenClock(start)
	s := newTestStore(t, sessions.Options{Normal: sessions.Timeouts{Idle: time.Hour, Absolute: time.Hour}, Now: nowFn})
	ctx := t.Context()

	created, err := s.Create(ctx, 1, sessions.CreateOptions{AuthMethod: "oidc"})
	require.NoError(t, err)

	// Inside throttle: caller's cached value is returned, no UPDATE runs.
	advance(30 * time.Second)
	got, err := s.Touch(ctx, created.ID, created.LastSeenAt)
	require.NoError(t, err)
	assert.Equal(t, created.LastSeenAt, got, "touch within throttle must not advance the cached value")

	// Past throttle: UPDATE runs, returned value is the new clock reading.
	advance(2 * time.Minute)
	got2, err := s.Touch(ctx, created.ID, created.LastSeenAt)
	require.NoError(t, err)
	assert.True(t, got2.After(created.LastSeenAt), "touch past throttle must advance last_seen_at")
}

// TestUpdateLastAuthAt_StampsAndBumpsLastSeen pins the contract Phase 5 relies on: a successful reauth resets BOTH freshness and idle
// timers. IsFresh flips back to true; idle countdown restarts.
func TestUpdateLastAuthAt_StampsAndBumpsLastSeen(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC)
	nowFn, advance := frozenClock(start)
	s := newTestStore(t, sessions.Options{
		Normal:       sessions.Timeouts{Idle: time.Hour, Absolute: 24 * time.Hour},
		ReauthWindow: 30 * time.Minute,
		Now:          nowFn,
	})
	ctx := t.Context()

	created, err := s.Create(ctx, 1, sessions.CreateOptions{AuthMethod: "oidc"})
	require.NoError(t, err)
	assert.True(t, s.IsFresh(created), "freshly minted session must be fresh")

	advance(45 * time.Minute) // past reauth window
	stale, err := s.Get(ctx, created.ID)
	require.NoError(t, err)
	assert.False(t, s.IsFresh(stale), "session past reauth window must be stale")

	require.NoError(t, s.UpdateLastAuthAt(ctx, created.ID))

	refreshed, err := s.Get(ctx, created.ID)
	require.NoError(t, err)
	assert.True(t, s.IsFresh(refreshed), "session must be fresh after UpdateLastAuthAt")
	assert.WithinDuration(t, nowFn(), refreshed.LastSeenAt, time.Second,
		"UpdateLastAuthAt must also bump last_seen_at — successful auth is activity")
}

// TestUpdateLastAuthAt_UnknownIDReturnsNotFound covers the defensive branch:
// a stale cookie that no longer matches a row must not silently succeed.
func TestUpdateLastAuthAt_UnknownIDReturnsNotFound(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, sessions.Options{})
	err := s.UpdateLastAuthAt(t.Context(), make([]byte, sessions.IDLen))
	require.ErrorIs(t, err, sessions.ErrNotFound)
}

func TestDelete_IsIdempotent(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, sessions.Options{})
	ctx := t.Context()

	sess, err := s.Create(ctx, 1, sessions.CreateOptions{})
	require.NoError(t, err)
	require.NoError(t, s.Delete(ctx, sess.ID))
	require.NoError(t, s.Delete(ctx, sess.ID), "second delete of same id must not error")
	require.NoError(t, s.Delete(ctx, make([]byte, sessions.IDLen)), "delete of unknown id must not error")
}

func TestCleanupExpired_RemovesOnlyExpired(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC)
	nowFn, advance := frozenClock(start)
	s := newTestStore(t, sessions.Options{
		Normal: sessions.Timeouts{Idle: time.Hour, Absolute: time.Hour},
		Now:    nowFn,
	})
	ctx := t.Context()

	active, err := s.Create(ctx, 1, sessions.CreateOptions{})
	require.NoError(t, err)

	// Advance past the absolute cap so the first row expires, then create a fresh row.
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
