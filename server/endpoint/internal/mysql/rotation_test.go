package mysql_test

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/endpoint/internal/mysql"
)

// rotationGrace is the grace window the tests use; long enough to cover
// the test's own setup latency, short enough that the
// "after-grace-rejection" branch is exercised in milliseconds.
const rotationGrace = 500 * time.Millisecond

// TestRotateHostToken_HappyPath asserts the contract: a successful
// rotation returns a fresh raw token + a non-empty previous-token-id
// prefix; the new token verifies; the old token still verifies during
// grace; the rotation is recorded as MatchedPrevious=true on a
// previous-token verify so the service layer's auto-rotate trigger
// stays idle.
func TestRotateHostToken_HappyPath(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	reg, err := s.Register(ctx, mysql.RegisterRequest{
		HostID: testUUID, Hostname: "h", AgentVersion: "v", OSVersion: "o", SourceIP: "127.0.0.1",
	})
	require.NoError(t, err)

	// VerifyWithMeta on the freshly-issued token reports the current
	// token, no previous match, and a fresh issued_at.
	pre, err := s.VerifyWithMeta(ctx, reg.HostToken)
	require.NoError(t, err)
	assert.False(t, pre.MatchedPrevious)
	assert.NotEmpty(t, pre.CurrentTokenID)
	assert.WithinDuration(t, time.Now(), pre.TokenIssuedAt, 5*time.Second)

	rot, err := s.RotateHostToken(ctx, testUUID, pre.CurrentTokenID, rotationGrace)
	require.NoError(t, err)
	assert.NotEmpty(t, rot.NewToken)
	assert.NotEqual(t, reg.HostToken, rot.NewToken)
	assert.Len(t, rot.PreviousTokenIDPrefix, 8) // 4 bytes hex == 8 chars

	// The new token verifies as the current token; rotation is not in
	// flight from this row's POV (we just committed it).
	post, err := s.VerifyWithMeta(ctx, rot.NewToken)
	require.NoError(t, err)
	assert.Equal(t, testUUID, post.HostID)
	assert.False(t, post.MatchedPrevious)
	assert.WithinDuration(t, time.Now(), post.TokenIssuedAt, 2*time.Second,
		"a freshly rotated token should bump host_token_issued_at to NOW()")

	// The OLD token still verifies during grace, AND surfaces
	// MatchedPrevious=true so the service layer knows another rotation
	// is in flight and must not trigger a fresh one.
	prev, err := s.VerifyWithMeta(ctx, reg.HostToken)
	require.NoError(t, err)
	assert.Equal(t, testUUID, prev.HostID)
	assert.True(t, prev.MatchedPrevious)
}

// TestRotateHostToken_OldTokenRejectedAfterGrace validates the grace
// boundary: as soon as previous_token_expires_at is in the past, the
// old token must stop verifying. Without this, a leaked token would
// stay valid forever even after rotation.
func TestRotateHostToken_OldTokenRejectedAfterGrace(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	reg, err := s.Register(ctx, mysql.RegisterRequest{
		HostID: testUUID, Hostname: "h", AgentVersion: "v", OSVersion: "o", SourceIP: "127.0.0.1",
	})
	require.NoError(t, err)
	pre, err := s.VerifyWithMeta(ctx, reg.HostToken)
	require.NoError(t, err)

	const tinyGrace = 50 * time.Millisecond
	_, err = s.RotateHostToken(ctx, testUUID, pre.CurrentTokenID, tinyGrace)
	require.NoError(t, err)

	// Sleep past the grace boundary; the old token must now be rejected.
	// Use a comfortable margin so the test doesn't flake on a slow CI
	// runner.
	time.Sleep(tinyGrace + 250*time.Millisecond)

	_, err = s.Verify(ctx, reg.HostToken)
	assert.ErrorIs(t, err, mysql.ErrTokenMismatch,
		"old token must stop verifying once previous_token_expires_at is in the past")
}

// TestRotateHostToken_RaceLoses asserts that the optimistic-lock keyed
// on currentTokenID rejects a stale rotate attempt: if rotation A
// commits between caller B's VerifyWithMeta and caller B's
// RotateHostToken, B's UPDATE matches zero rows and B gets
// ErrRotateRaced. This is the contract the service layer relies on to
// keep concurrent verifies from double-rotating.
func TestRotateHostToken_RaceLoses(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	reg, err := s.Register(ctx, mysql.RegisterRequest{
		HostID: testUUID, Hostname: "h", AgentVersion: "v", OSVersion: "o", SourceIP: "127.0.0.1",
	})
	require.NoError(t, err)
	pre, err := s.VerifyWithMeta(ctx, reg.HostToken)
	require.NoError(t, err)

	// First rotation succeeds.
	_, err = s.RotateHostToken(ctx, testUUID, pre.CurrentTokenID, rotationGrace)
	require.NoError(t, err)

	// A second rotation using the SAME (now stale) currentTokenID must
	// lose the race.
	_, err = s.RotateHostToken(ctx, testUUID, pre.CurrentTokenID, rotationGrace)
	assert.ErrorIs(t, err, mysql.ErrRotateRaced)
}

// TestRotateHostToken_ConcurrentVerifiesProduceOneRotation throws N
// goroutines at RotateHostToken with the same currentTokenID. Exactly
// one must commit; the rest must observe ErrRotateRaced. This is the
// property the service-level "verify-time auto-rotate" relies on to
// not produce a flurry of rotations under burst traffic.
func TestRotateHostToken_ConcurrentVerifiesProduceOneRotation(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	reg, err := s.Register(ctx, mysql.RegisterRequest{
		HostID: testUUID, Hostname: "h", AgentVersion: "v", OSVersion: "o", SourceIP: "127.0.0.1",
	})
	require.NoError(t, err)
	pre, err := s.VerifyWithMeta(ctx, reg.HostToken)
	require.NoError(t, err)

	const N = 16
	var (
		wg        sync.WaitGroup
		successes int
		races     int
		mu        sync.Mutex
	)
	wg.Add(N)
	for range N {
		go func() {
			defer wg.Done()
			_, err := s.RotateHostToken(ctx, testUUID, pre.CurrentTokenID, rotationGrace)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				successes++
			case mysql.ErrRotateRaced.Error() == err.Error():
				races++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 1, successes, "exactly one concurrent rotation must commit")
	assert.Equal(t, N-1, races, "every other concurrent rotation must observe ErrRotateRaced")
}

// TestRotateHostToken_RejectsRevoked: revoking the enrollment must
// prevent any further rotation. Otherwise an attacker who has the
// (revoked) token could nudge the row back into a usable state.
func TestRotateHostToken_RejectsRevoked(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	reg, err := s.Register(ctx, mysql.RegisterRequest{
		HostID: testUUID, Hostname: "h", AgentVersion: "v", OSVersion: "o", SourceIP: "127.0.0.1",
	})
	require.NoError(t, err)
	pre, err := s.VerifyWithMeta(ctx, reg.HostToken)
	require.NoError(t, err)

	require.NoError(t, s.Revoke(ctx, testUUID, "compromised", "jane@example"))

	_, err = s.RotateHostToken(ctx, testUUID, pre.CurrentTokenID, rotationGrace)
	assert.ErrorIs(t, err, mysql.ErrRotateRaced,
		"rotation against a revoked enrollment must surface as a race rather than silently bring it back")
}

// TestRotateHostToken_RejectsBadInputs covers the input-validation
// contract: empty hostID / empty currentTokenID / non-positive grace
// are programmer errors, surfaced loudly so they fail at the boundary
// rather than leaking into the SQL.
func TestRotateHostToken_RejectsBadInputs(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	cases := []struct {
		name    string
		host    string
		curID   []byte
		grace   time.Duration
		wantSub string
	}{
		{"empty hostID", "", []byte{1, 2, 3, 4}, time.Second, "hostID is required"},
		{"empty currentTokenID", testUUID, nil, time.Second, "currentTokenID is required"},
		{"zero grace", testUUID, []byte{1, 2, 3, 4}, 0, "grace must be > 0"},
		{"negative grace", testUUID, []byte{1, 2, 3, 4}, -time.Second, "grace must be > 0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.RotateHostToken(ctx, tc.host, tc.curID, tc.grace)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)
		})
	}
}

// TestRotateHostToken_OverwritesPriorPrevious validates the rare double
// rotation case: if rotation N+1 fires while a previous-token grace
// from rotation N is still active, the previous slot is overwritten
// with the just-superseded token. The oldest token (originally enrolled)
// stops verifying immediately. Acceptable: a host that misses two
// rotation windows has been offline / unreachable long enough that
// re-enroll is the right recovery anyway.
func TestRotateHostToken_OverwritesPriorPrevious(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	reg, err := s.Register(ctx, mysql.RegisterRequest{
		HostID: testUUID, Hostname: "h", AgentVersion: "v", OSVersion: "o", SourceIP: "127.0.0.1",
	})
	require.NoError(t, err)
	v0, err := s.VerifyWithMeta(ctx, reg.HostToken)
	require.NoError(t, err)

	// First rotation: original token becomes "previous" in grace.
	rot1, err := s.RotateHostToken(ctx, testUUID, v0.CurrentTokenID, rotationGrace)
	require.NoError(t, err)
	v1, err := s.VerifyWithMeta(ctx, rot1.NewToken)
	require.NoError(t, err)

	// Second rotation: rot1.NewToken becomes "previous"; the original
	// reg.HostToken is no longer tracked.
	rot2, err := s.RotateHostToken(ctx, testUUID, v1.CurrentTokenID, rotationGrace)
	require.NoError(t, err)

	// The original token: not in current, not in previous; rejected.
	_, err = s.Verify(ctx, reg.HostToken)
	require.ErrorIs(t, err, mysql.ErrTokenMismatch)

	// rot1.NewToken: now the previous; verifies during grace.
	r1, err := s.VerifyWithMeta(ctx, rot1.NewToken)
	require.NoError(t, err)
	assert.True(t, r1.MatchedPrevious)

	// rot2.NewToken: current.
	r2, err := s.VerifyWithMeta(ctx, rot2.NewToken)
	require.NoError(t, err)
	assert.False(t, r2.MatchedPrevious)
}
