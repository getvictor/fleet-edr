package breakglass

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

// TokenKindBreakglassSetup is the bootstrap_tokens.kind value the
// break-glass redemption flow consumes. Reserved as a constant so
// future kinds (wave-2 invite tokens) cannot collide with the
// break-glass setup flow's WHERE clause.
const TokenKindBreakglassSetup = "breakglass_setup"

// TokenPlaintextBytes is the size of the random plaintext token in
// bytes BEFORE base64-url encoding. 32 bytes ≈ 256 bits of entropy:
// well above the brute-force threshold for a token that lives ≤ 1h.
const TokenPlaintextBytes = 32

// DefaultSetupTokenTTL is the wave-1 fallback when the operator does
// not pin EDR_BREAKGLASS_BOOTSTRAP_TOKEN_TTL. 1 hour matches the spec
// scenario "operator opens the redemption URL within the hour" and
// is short enough that an exfiltrated stderr log has bounded value.
const DefaultSetupTokenTTL = time.Hour

// ErrTokenInvalid is returned when no row matches the presented
// plaintext (after hashing). Distinct from ErrTokenExpired /
// ErrTokenConsumed so the redemption handler can map each to a
// directed reason in the audit row, while collapsing all three to a
// single 410-Gone wire response so an attacker cannot enumerate.
var ErrTokenInvalid = errors.New("breakglass: token invalid")

// ErrTokenExpired is returned when the matched row's expires_at has
// passed. Operator must have an admin reissue a token via the
// emergency runbook (wave-1) or the wave-2 admin endpoint.
var ErrTokenExpired = errors.New("breakglass: token expired")

// ErrTokenConsumed is returned when the matched row already has a
// non-NULL redeemed_at. Single-use means a second submission is
// always invalid even if the original redemption succeeded.
var ErrTokenConsumed = errors.New("breakglass: token already consumed")

// Token is the row shape callers see after Find / Issue. Only the
// hash is persisted; plaintext is returned exactly once at issue
// time. UserID is the bound break-glass account; FK CASCADE means a
// deleted user reaps their unredeemed tokens.
type Token struct {
	ID         int64         `db:"id"`
	UserID     sql.NullInt64 `db:"user_id"`
	Kind       string        `db:"kind"`
	IssuedAt   time.Time     `db:"issued_at"`
	ExpiresAt  time.Time     `db:"expires_at"`
	RedeemedAt sql.NullTime  `db:"redeemed_at"`
}

// TokenStore owns the bootstrap_tokens table.
type TokenStore struct {
	db *sqlx.DB
}

// NewTokenStore constructs a TokenStore. Panics if db is nil — a
// store backed by no connection has no useful behavior.
func NewTokenStore(db *sqlx.DB) *TokenStore {
	if db == nil {
		panic("breakglass.NewTokenStore: db must not be nil")
	}
	return &TokenStore{db: db}
}

// IssueSetup mints a new bootstrap token for the break-glass setup
// flow. Returns the plaintext (caller prints once and forgets) plus
// the persisted row (so the caller can reference the token id in
// audit rows). The plaintext is base64-url-encoded TokenPlaintextBytes
// of cryptographic randomness.
//
// MUST run synchronously: the caller (cmd/main on first boot) needs
// the plaintext available BEFORE the HTTP server starts accepting
// traffic so the printed banner predates any operator interaction.
func (s *TokenStore) IssueSetup(ctx context.Context, userID int64, ttl time.Duration) (plaintext string, t Token, err error) {
	if ttl <= 0 {
		ttl = DefaultSetupTokenTTL
	}
	plaintext, err = randomTokenPlaintext()
	if err != nil {
		return "", Token{}, fmt.Errorf("breakglass tokens: random: %w", err)
	}
	hash := hashTokenPlaintext(plaintext)
	issuedAt := time.Now()
	expiresAt := issuedAt.Add(ttl)
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO bootstrap_tokens (token_hash, user_id, kind, expires_at)
		VALUES (?, ?, ?, ?)
	`, hash[:], userID, TokenKindBreakglassSetup, expiresAt)
	if err != nil {
		return "", Token{}, fmt.Errorf("breakglass tokens: insert: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return "", Token{}, fmt.Errorf("breakglass tokens: last insert id: %w", err)
	}
	return plaintext, Token{
		ID:        id,
		UserID:    sql.NullInt64{Int64: userID, Valid: true},
		Kind:      TokenKindBreakglassSetup,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
	}, nil
}

// FindValid returns the bootstrap_tokens row matching the presented
// plaintext (after SHA-256 hashing) when the row exists, has not
// expired, and has not been redeemed. Distinguishes the three
// failure modes via typed errors so the audit row records the
// precise reason; the caller maps all three to a single 410-Gone
// wire response.
//
// Reads via a constant-time hash compare so a timing-attack on the
// stored hash cannot enumerate token existence. The UNIQUE index on
// token_hash means MySQL itself does the constant-time comparison;
// the explicit subtle.ConstantTimeCompare is defense in depth in
// case a future migration drops the unique constraint.
func (s *TokenStore) FindValid(ctx context.Context, plaintext string, now time.Time) (*Token, error) {
	hash := hashTokenPlaintext(plaintext)
	var t Token
	err := s.db.GetContext(ctx, &t, `
		SELECT id, user_id, kind, issued_at, expires_at, redeemed_at
		FROM bootstrap_tokens
		WHERE token_hash = ? AND kind = ?
	`, hash[:], TokenKindBreakglassSetup)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTokenInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("breakglass tokens: lookup: %w", err)
	}
	// Defense-in-depth: re-fetch the hash and compare in constant
	// time. UNIQUE(token_hash) means the SELECT already matched
	// exactly the right row, but a future schema change that drops
	// the index should not silently weaken this check.
	var got struct {
		Hash []byte `db:"token_hash"`
	}
	if err := s.db.GetContext(ctx, &got, `
		SELECT token_hash FROM bootstrap_tokens WHERE id = ?
	`, t.ID); err != nil {
		return nil, fmt.Errorf("breakglass tokens: hash compare: %w", err)
	}
	if subtle.ConstantTimeCompare(got.Hash, hash[:]) != 1 {
		return nil, ErrTokenInvalid
	}
	if t.RedeemedAt.Valid {
		return nil, ErrTokenConsumed
	}
	if !t.ExpiresAt.After(now) {
		return nil, ErrTokenExpired
	}
	return &t, nil
}

// MarkRedeemed sets redeemed_at on the row identified by id, scoped
// to a still-unredeemed row so a concurrent second redemption sees
// zero rows affected and the caller surfaces ErrTokenConsumed.
//
// MUST run inside the same transaction as the user-mutation +
// credential-persist + identity-insert it gates: the redemption is
// the atomic gate that prevents replay against a partially-applied
// account state. Caller passes the transaction's executor.
func (s *TokenStore) MarkRedeemed(ctx context.Context, ec Executor, id int64) error {
	res, err := ec.ExecContext(ctx, `
		UPDATE bootstrap_tokens
		SET redeemed_at = NOW(6)
		WHERE id = ? AND redeemed_at IS NULL
	`, id)
	if err != nil {
		return fmt.Errorf("breakglass tokens: mark redeemed: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("breakglass tokens: rows affected: %w", err)
	}
	if n == 0 {
		// A concurrent caller won the race or the row vanished.
		// Either way, this attempt loses; surface ErrTokenConsumed.
		return ErrTokenConsumed
	}
	return nil
}

// Executor is the executor subset MarkRedeemed accepts. *sqlx.Tx
// implements it; tests pass *sqlx.DB. Named per the Go convention
// (single-method interface ends in -er).
type Executor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// randomTokenPlaintext returns a base64-url-encoded
// TokenPlaintextBytes of randomness. base64-url so the token slots
// directly into a query string without escaping; 32 bytes for ~256
// bits of entropy.
func randomTokenPlaintext() (string, error) {
	buf := make([]byte, TokenPlaintextBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// hashTokenPlaintext is the SHA-256 of the plaintext bytes the
// store persists. The hash is unkeyed: the plaintext is 256 bits of
// cryptographic randomness so the hash's preimage-resistance derives
// from the input entropy rather than a server secret. We do NOT use
// argon2 here because the token's TTL (≤ 1h) and one-shot redemption
// mean an offline attack on the stored hash has at most minutes to
// be useful, and the SHA-256 hash makes a stolen DB dump useless.
func hashTokenPlaintext(plaintext string) [32]byte {
	return sha256.Sum256([]byte(plaintext))
}
