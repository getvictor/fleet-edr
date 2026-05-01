// Package sessions owns the `sessions` table that backs Phase 3 UI cookie auth. A
// session is a server-side row keyed by the SHA-256 digest of a 32-byte random token.
// The cookie carries the raw token (base64url-encoded); the DB stores only the digest,
// mirroring the pattern enrollment tokens use so a database compromise does not
// immediately yield replayable bearer credentials. CSRF tokens are per-session, also
// 32 random bytes, returned to the client in the login response body and sent back as
// `X-CSRF-Token` on unsafe methods — those are stored raw because CSRF comparisons
// happen via constant-time compare, not indexed lookup.
package sessions

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

// DefaultTTL is the session lifetime. 12 hours matches common SaaS admin-console
// defaults: long enough that operators aren't constantly re-logging in, short enough
// that a stolen cookie expires before the end of a work day.
const DefaultTTL = 12 * time.Hour

// IDLen is the session id + CSRF token length in bytes. 32 bytes ≈ 256 bits of entropy,
// well past any practical guessing bound.
const IDLen = 32

// ErrNotFound is returned by Get when no active session matches the id. Expired rows
// are treated as not-found so callers can translate both to the same 401.
var ErrNotFound = errors.New("sessions: not found or expired")

// Session is the fully-loaded row as the caller sees it. ID is the PLAINTEXT token —
// what the client puts in its cookie. The server only ever persists SHA-256(ID); the
// plaintext lives in memory for the lifetime of the request that created it and
// inside the cookie the client holds. CSRFToken is kept as []byte rather than an
// encoded string so constant-time compares in the authn middleware stay honest.
type Session struct {
	ID         []byte
	UserID     int64
	CSRFToken  []byte
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
}

// digest returns SHA-256 of the session's raw-bytes id. It's the value we store and
// look up by — the one-way hash ensures a DB leak does not yield replayable cookies.
func digest(id []byte) []byte {
	h := sha256.Sum256(id)
	return h[:]
}

// Store owns the sessions table.
type Store struct {
	db  *sqlx.DB
	ttl time.Duration
	// now is the clock source; overridable for tests that need to manipulate expires_at
	// without wall-clock coupling. Defaults to time.Now.UTC.
	now func() time.Time
}

// Options customise Store behaviour. Leave unset fields as zero values to use defaults.
type Options struct {
	// TTL is the session lifetime. Zero means DefaultTTL.
	TTL time.Duration
	// Now is the clock source. Nil means time.Now.UTC.
	Now func() time.Time
}

// New constructs a Store over an existing sqlx.DB handle.
func New(db *sqlx.DB, opts Options) *Store {
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Store{db: db, ttl: ttl, now: now}
}

// Create inserts a new session for userID and returns the fully-populated row with
// the PLAINTEXT id in Session.ID (that's what the caller puts in the Set-Cookie). The
// DB row stores SHA-256(id) so a dump of the sessions table cannot be replayed as
// active cookies.
func (s *Store) Create(ctx context.Context, userID int64) (*Session, error) {
	id, err := randomBytes(IDLen)
	if err != nil {
		return nil, fmt.Errorf("generate session id: %w", err)
	}
	csrf, err := randomBytes(IDLen)
	if err != nil {
		return nil, fmt.Errorf("generate csrf token: %w", err)
	}
	now := s.now()
	expires := now.Add(s.ttl)
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, csrf_token, expires_at)
		VALUES (?, ?, ?, ?)
	`, digest(id), userID, csrf, expires); err != nil {
		return nil, fmt.Errorf("insert session: %w", err)
	}
	return &Session{
		ID: id, UserID: userID, CSRFToken: csrf,
		CreatedAt: now, LastSeenAt: now, ExpiresAt: expires,
	}, nil
}

// Get takes the plaintext id from the cookie, hashes it, and looks up the row by that
// digest. Returns ErrNotFound if missing / expired. We filter `expires_at > NOW()`
// inside the SQL so a stale row is indistinguishable from a nonexistent one — the
// middleware can treat both as "401 invalid_session".
func (s *Store) Get(ctx context.Context, plaintextID []byte) (*Session, error) {
	if len(plaintextID) != IDLen {
		return nil, ErrNotFound
	}
	var row struct {
		UserID     int64     `db:"user_id"`
		CSRFToken  []byte    `db:"csrf_token"`
		CreatedAt  time.Time `db:"created_at"`
		LastSeenAt time.Time `db:"last_seen_at"`
		ExpiresAt  time.Time `db:"expires_at"`
	}
	// `now` is passed in so tests can drive the clock; production uses s.now().
	err := s.db.GetContext(ctx, &row, `
		SELECT user_id, csrf_token, created_at, last_seen_at, expires_at
		FROM sessions
		WHERE id = ? AND expires_at > ?
	`, digest(plaintextID), s.now())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query session: %w", err)
	}
	return &Session{
		// Return the plaintext id the caller passed in so downstream code (e.g.
		// idPrefix for audit logs) can render a stable prefix for correlation.
		ID: plaintextID, UserID: row.UserID, CSRFToken: row.CSRFToken,
		CreatedAt: row.CreatedAt, LastSeenAt: row.LastSeenAt, ExpiresAt: row.ExpiresAt,
	}, nil
}

// Delete removes a session by plaintext id. Idempotent — no error on a row that
// doesn't exist so logout works even when the cookie is already stale on the client.
func (s *Store) Delete(ctx context.Context, plaintextID []byte) error {
	if len(plaintextID) != IDLen {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, digest(plaintextID)); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// CleanupExpired removes every expired session row. Intended to be called on a timer
// by main.go so the table doesn't grow unbounded. Returns the number of rows removed.
func (s *Store) CleanupExpired(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, s.now())
	if err != nil {
		return 0, fmt.Errorf("cleanup expired sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// TTL returns the configured session lifetime. Exposed so the session handler can set
// the cookie's Max-Age consistently with the DB row's expires_at.
func (s *Store) TTL() time.Duration { return s.ttl }

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
