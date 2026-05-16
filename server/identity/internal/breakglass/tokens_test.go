//go:build integration

package breakglass_test

import (
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/internal/breakglass"
	"github.com/fleetdm/edr/server/identity/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

// newTokenStore opens a fresh DB, applies identity schema, and seeds a placeholder admin user that bootstrap tokens can FK against.
// Returns the store + the seeded user id so individual tests don't each repeat the seeding.
func newTokenStore(t *testing.T) (*breakglass.TokenStore, *sqlx.DB, int64) {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	res, err := db.ExecContext(t.Context(),
		`INSERT INTO users (email, is_breakglass) VALUES (?, ?)`,
		"admin@fleet-edr.local", true)
	require.NoError(t, err)
	uid, err := res.LastInsertId()
	require.NoError(t, err)
	return breakglass.NewTokenStore(db), db, uid
}

// IssueSetup → FindValid round-trip returns the same row with the same expires_at (within MySQL's 6-digit precision), and the
// plaintext is non-trivial. Pinned because a regression that issued the token but stored a different hash would render the token
// permanently unusable while looking healthy at issue time.
func TestIssueSetup_RoundTrip(t *testing.T) {
	s, _, uid := newTokenStore(t)

	plaintext, tok, err := s.IssueSetup(t.Context(), uid, time.Hour)
	require.NoError(t, err)
	assert.NotEmpty(t, plaintext)
	assert.Greater(t, len(plaintext), 32, "plaintext base64 of 32 random bytes ≈ 43 chars")
	assert.Equal(t, breakglass.TokenKindBreakglassSetup, tok.Kind)

	got, err := s.FindValid(t.Context(), plaintext, time.Now())
	require.NoError(t, err)
	assert.Equal(t, tok.ID, got.ID)
	assert.True(t, got.UserID.Valid)
	assert.Equal(t, uid, got.UserID.Int64)
	assert.False(t, got.RedeemedAt.Valid, "fresh token has no redeemed_at")
}

// FindValid returns ErrTokenInvalid for a plaintext that doesn't match any persisted hash. Includes a syntactically-correct-but-
// unknown token to verify the lookup hashes the input rather than comparing plaintext directly (which would never match).
func TestFindValid_Unknown(t *testing.T) {
	s, _, _ := newTokenStore(t)
	_, err := s.FindValid(t.Context(), "this-is-not-a-real-token", time.Now())
	assert.ErrorIs(t, err, breakglass.ErrTokenInvalid)
}

// FindValid returns ErrTokenExpired when the row's expires_at is in the past per the now-frozen clock. The MySQL row remains; only the
// in-Go check rejects.
func TestFindValid_Expired(t *testing.T) {
	s, _, uid := newTokenStore(t)
	plaintext, tok, err := s.IssueSetup(t.Context(), uid, time.Hour)
	require.NoError(t, err)

	tooLate := tok.ExpiresAt.Add(time.Minute)
	_, err = s.FindValid(t.Context(), plaintext, tooLate)
	assert.ErrorIs(t, err, breakglass.ErrTokenExpired)
}

// MarkRedeemed once flips redeemed_at; second call returns ErrTokenConsumed and FindValid likewise rejects. Pinned because the
// single-use invariant is the entire security guarantee of the bootstrap flow.
func TestMarkRedeemed_SingleUse(t *testing.T) {
	s, db, uid := newTokenStore(t)
	plaintext, tok, err := s.IssueSetup(t.Context(), uid, time.Hour)
	require.NoError(t, err)

	require.NoError(t, s.MarkRedeemed(t.Context(), db, tok.ID))

	// Second mark fails.
	err = s.MarkRedeemed(t.Context(), db, tok.ID)
	assert.ErrorIs(t, err, breakglass.ErrTokenConsumed)

	// FindValid also rejects after redemption.
	_, err = s.FindValid(t.Context(), plaintext, time.Now())
	assert.ErrorIs(t, err, breakglass.ErrTokenConsumed)
}

// IssueSetup falls through to DefaultSetupTokenTTL when ttl <= 0. Pinned because callers pass the configured duration verbatim and a
// config with no TTL would otherwise produce already-expired tokens.
func TestIssueSetup_DefaultsToWaveOneTTL(t *testing.T) {
	s, _, uid := newTokenStore(t)
	_, tok, err := s.IssueSetup(t.Context(), uid, 0)
	require.NoError(t, err)
	delta := time.Until(tok.ExpiresAt)
	assert.Greater(t, delta, breakglass.DefaultSetupTokenTTL-time.Minute,
		"ttl=0 should fall through to ~%s default", breakglass.DefaultSetupTokenTTL)
}

// Plaintext format: base64-url, no padding, no whitespace. Pinned so
// a stderr banner can include the URL without escaping concerns.
func TestIssueSetup_PlaintextFormat(t *testing.T) {
	s, _, uid := newTokenStore(t)
	plaintext, _, err := s.IssueSetup(t.Context(), uid, time.Hour)
	require.NoError(t, err)
	assert.NotContains(t, plaintext, "=", "RawURLEncoding strips padding")
	assert.NotContains(t, plaintext, " ", "no whitespace")
	assert.NotContains(t, plaintext, "\n", "no newlines")
	assert.False(t, strings.ContainsAny(plaintext, "+/"),
		"URL-safe alphabet only (- and _, not + and /)")
}

// IssueSetup supersedes any prior unredeemed setup token for the same user so a server restart cycle doesn't leave the
// previously-printed banner URL valid alongside the freshly-printed one. The cmd/main first-boot path re-runs IssueSetup on
// every restart while no WebAuthn credential exists; without supersession the operator accumulates one independently-redeemable
// bearer credential per restart, each viable until its own TTL elapses. Pinned because regressing this would re-introduce the
// credential-lifetime bug QA surfaced before v0.1.
func TestIssueSetup_SupersedesPriorUnredeemed(t *testing.T) {
	s, db, uid := newTokenStore(t)
	ctx := t.Context()

	priorPlaintext, priorTok, err := s.IssueSetup(ctx, uid, time.Hour)
	require.NoError(t, err)

	freshPlaintext, freshTok, err := s.IssueSetup(ctx, uid, time.Hour)
	require.NoError(t, err)
	require.NotEqual(t, priorPlaintext, freshPlaintext)
	require.NotEqual(t, priorTok.ID, freshTok.ID)

	// Prior plaintext no longer resolves: the row was deleted by the
	// supersession step inside IssueSetup's transaction.
	_, err = s.FindValid(ctx, priorPlaintext, time.Now())
	require.Error(t, err, "prior plaintext must not resolve after a fresh IssueSetup")

	// Fresh plaintext does resolve.
	got, err := s.FindValid(ctx, freshPlaintext, time.Now())
	require.NoError(t, err)
	assert.Equal(t, freshTok.ID, got.ID)

	// At most one unredeemed setup token row exists for the user (the fresh one). Any prior row was deleted, not just hidden behind a
	// flag.
	var unredeemedCount int
	require.NoError(t, db.GetContext(ctx, &unredeemedCount, `
		SELECT COUNT(*) FROM bootstrap_tokens
		WHERE user_id = ? AND kind = ? AND redeemed_at IS NULL
	`, uid, breakglass.TokenKindBreakglassSetup))
	assert.Equal(t, 1, unredeemedCount,
		"exactly one unredeemed setup token per user after a re-issue")
}

// IssueSetup only supersedes unredeemed tokens; redeemed-and-historic rows are preserved. The break-glass surface treats redeemed_at
// as the canonical "this token was used" marker; deleting redeemed rows would erase the audit trail of which tokens were spent.
// Pinned so the supersession sweep stays narrow.
func TestIssueSetup_LeavesRedeemedRowsIntact(t *testing.T) {
	s, db, uid := newTokenStore(t)
	ctx := t.Context()

	// Mint + mark redeemed: simulates the post-redemption state where the operator has a registered WebAuthn credential. MarkRedeemed
	// requires a transactional executor; the equivalent direct UPDATE keeps this test independent of the redemption transaction machinery
	// while pinning the same row shape.
	_, redeemedTok, err := s.IssueSetup(ctx, uid, time.Hour)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx,
		`UPDATE bootstrap_tokens SET redeemed_at = NOW(6) WHERE id = ?`,
		redeemedTok.ID)
	require.NoError(t, err)

	// New IssueSetup (simulates the operator's "register a second key"
	// SQL-recovery flow) must NOT touch the redeemed row.
	_, _, err = s.IssueSetup(ctx, uid, time.Hour)
	require.NoError(t, err)

	var redeemedCount int
	require.NoError(t, db.GetContext(ctx, &redeemedCount, `
		SELECT COUNT(*) FROM bootstrap_tokens
		WHERE user_id = ? AND kind = ? AND redeemed_at IS NOT NULL
	`, uid, breakglass.TokenKindBreakglassSetup))
	assert.Equal(t, 1, redeemedCount,
		"redeemed rows must survive a subsequent IssueSetup")
}
