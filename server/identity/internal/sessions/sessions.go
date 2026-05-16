// Package sessions owns the `sessions` table that backs UI cookie auth. A session is a server-side row keyed by the SHA-256 digest
// of a 32-byte random token. The cookie carries the raw token (base64url-encoded); the DB stores only the digest, mirroring the
// pattern enrollment tokens use so a database compromise does not immediately yield replayable bearer credentials. CSRF tokens are
// per-session, also 32 random bytes, returned to the client in the login response body and sent back as `X-CSRF-Token` on unsafe
// methods — those are stored raw because CSRF comparisons happen via constant-time compare, not indexed lookup.
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

// Phase 5 lifetime defaults: idle (inactivity) + absolute (hard cap) per session class. Normal sessions get the lenient pair; break-
// glass sessions get the strict pair so a stolen recovery cookie expires before the end of an incident shift. The pre-Phase-5 flat 12h
// DefaultTTL is gone — every caller is now class-aware.
const (
	DefaultIdleTimeout               = 8 * time.Hour
	DefaultAbsoluteTimeout           = 24 * time.Hour
	DefaultBreakglassIdleTimeout     = 15 * time.Minute
	DefaultBreakglassAbsoluteTimeout = 1 * time.Hour
)

// DefaultReauthWindow is the freshness window the chokepoint reads via Actor.SessionFresh. last_auth_at within this window means the
// operator has proven possession of credentials recently enough to run destructive actions without re-prompting.
const DefaultReauthWindow = 30 * time.Minute

// touchThrottle is the minimum interval between sliding extensions of one session's last_seen_at column. Middleware skips the UPDATE
// when the cached value is fresher than this; idle-timeout granularity is therefore 1 minute, invisible at the 8h scale and caps the
// write rate at 1/min/active session.
const touchThrottle = 1 * time.Minute

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
//
// AuthMethod records how the session was minted ("local_password" or "oidc").
// Phase 2's chokepoint reads it through Service.LoadActor so the actor's
// AuthMethod field reflects ground truth instead of a hardcoded default.
// IdentityID FKs into the identities table; nullable so legacy local-password
// rows (pre-Phase-4) and tests that don't track identities can stay valid.
//
// LastAuthAt records the most recent authentication event for this session
// — initial login, OIDC reauth callback, or break-glass reauth POST.
// Phase 5's chokepoint reads it via Store.IsFresh / Actor.SessionFresh
// to gate destructive actions.
type Session struct {
	ID         []byte
	UserID     int64
	IdentityID *int64
	AuthMethod string
	CSRFToken  []byte
	CreatedAt  time.Time
	LastSeenAt time.Time
	LastAuthAt time.Time
	ExpiresAt  time.Time
}

// digest returns SHA-256 of the session's raw-bytes id. It's the value we store and
// look up by — the one-way hash ensures a DB leak does not yield replayable cookies.
func digest(id []byte) []byte {
	h := sha256.Sum256(id)
	return h[:]
}

// Timeouts is the idle/absolute pair that gates one session class's lifetime. Idle is the inactivity cap (last_seen_at + idle);
// absolute is the hard cap (created_at + absolute). Either elapsing makes the row not-found at lookup time.
type Timeouts struct {
	Idle     time.Duration
	Absolute time.Duration
}

// Store owns the sessions table.
type Store struct {
	db         *sqlx.DB
	normal     Timeouts
	breakglass Timeouts
	reauthWin  time.Duration
	// now is the clock source; overridable for tests that need to manipulate expires_at
	// without wall-clock coupling. Defaults to time.Now.UTC.
	now func() time.Time
}

// Options customise Store behaviour. Leave unset fields as zero values to use defaults.
type Options struct {
	// Normal is the timeout pair for OIDC-minted sessions. Zero values fall through to DefaultIdleTimeout + DefaultAbsoluteTimeout.
	Normal Timeouts
	// Breakglass is the strict timeout pair for the recovery surface. Zero values fall through to DefaultBreakglassIdleTimeout +
	// DefaultBreakglassAbsoluteTimeout.
	Breakglass Timeouts
	// ReauthWindow is the last_auth_at freshness gate. Zero means
	// DefaultReauthWindow.
	ReauthWindow time.Duration
	// Now is the clock source. Nil means time.Now.UTC.
	Now func() time.Time
}

// New constructs a Store over an existing sqlx.DB handle.
func New(db *sqlx.DB, opts Options) *Store {
	normal := opts.Normal
	if normal.Idle <= 0 {
		normal.Idle = DefaultIdleTimeout
	}
	if normal.Absolute <= 0 {
		normal.Absolute = DefaultAbsoluteTimeout
	}
	bg := opts.Breakglass
	if bg.Idle <= 0 {
		bg.Idle = DefaultBreakglassIdleTimeout
	}
	if bg.Absolute <= 0 {
		bg.Absolute = DefaultBreakglassAbsoluteTimeout
	}
	rw := opts.ReauthWindow
	if rw <= 0 {
		rw = DefaultReauthWindow
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Store{db: db, normal: normal, breakglass: bg, reauthWin: rw, now: now}
}

// timeoutsFor returns the (idle, absolute) pair appropriate to the session's auth_method. Phase 4 design pins
// auth_method=='local_password' to the break-glass surface; OIDC sessions get the normal pair.
func (s *Store) timeoutsFor(authMethod string) Timeouts {
	if authMethod == "local_password" {
		return s.breakglass
	}
	return s.normal
}

// CreateOptions carry the per-session metadata Phase 4 records on the row. Zero AuthMethod defaults to "local_password" for legacy
// callers; nil IdentityID is valid (legacy + tests).
type CreateOptions struct {
	IdentityID *int64
	AuthMethod string
}

// Create inserts a new session for userID and returns the fully-populated row with
// the PLAINTEXT id in Session.ID (that's what the caller puts in the Set-Cookie). The
// DB row stores SHA-256(id) so a dump of the sessions table cannot be replayed as
// active cookies. opts pins identity_id + auth_method for the chokepoint to consume
// later via the session middleware.
//
// Phase 5: expires_at is the absolute cap (created_at + Timeouts.Absolute) for the
// session's class. The idle cap is enforced at Get time against last_seen_at, not
// stored on the row. last_auth_at is initialised to NOW() since a fresh session is
// definitionally fresh.
func (s *Store) Create(ctx context.Context, userID int64, opts CreateOptions) (*Session, error) {
	id, err := randomBytes(IDLen)
	if err != nil {
		return nil, fmt.Errorf("generate session id: %w", err)
	}
	csrf, err := randomBytes(IDLen)
	if err != nil {
		return nil, fmt.Errorf("generate csrf token: %w", err)
	}
	authMethod := opts.AuthMethod
	if authMethod == "" {
		authMethod = "local_password"
	}
	now := s.now()
	expires := now.Add(s.timeoutsFor(authMethod).Absolute)
	// All three timestamps are set explicitly from the store's clock so frozen- clock tests and the production wall-clock path stay
	// self-consistent. The columns' DB defaults (CURRENT_TIMESTAMP(6) on insert, ON UPDATE for last_seen_at) only apply when the field is
	// omitted from the INSERT or when an UPDATE doesn't name last_seen_at — which Touch / UpdateLastAuthAt always do.
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, identity_id, auth_method, csrf_token,
			created_at, last_seen_at, last_auth_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, digest(id), userID, nullInt64Ptr(opts.IdentityID), authMethod, csrf,
		now, now, now, expires); err != nil {
		return nil, fmt.Errorf("insert session: %w", err)
	}
	return &Session{
		ID: id, UserID: userID, IdentityID: opts.IdentityID, AuthMethod: authMethod,
		CSRFToken: csrf, CreatedAt: now, LastSeenAt: now, LastAuthAt: now, ExpiresAt: expires,
	}, nil
}

// nullInt64Ptr converts a *int64 to a sql-nullable input the *sqlx driver passes through to MySQL as NULL for nil and integer for
// non-nil. Local helper so the Create signature stays clean.
func nullInt64Ptr(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

// Get takes the plaintext id from the cookie, hashes it, and looks up the row by that
// digest. Returns ErrNotFound when no row matches OR when either timeout has elapsed.
// Both surfaces map to the same 401 invalid_session in the middleware so a stale row
// is indistinguishable from a nonexistent one.
//
// Phase 5: idle (last_seen_at + Timeouts.Idle) and absolute (created_at +
// Timeouts.Absolute) caps are enforced in Go after the row is fetched. The class-
// specific timeout pair depends on auth_method (break-glass uses the strict pair).
// Doing the comparison in Go keeps the SQL identical for both classes; the post-
// fetch cost is two time comparisons against an already-loaded row.
func (s *Store) Get(ctx context.Context, plaintextID []byte) (*Session, error) {
	if len(plaintextID) != IDLen {
		return nil, ErrNotFound
	}
	var row struct {
		UserID     int64         `db:"user_id"`
		IdentityID sql.NullInt64 `db:"identity_id"`
		AuthMethod string        `db:"auth_method"`
		CSRFToken  []byte        `db:"csrf_token"`
		CreatedAt  time.Time     `db:"created_at"`
		LastSeenAt time.Time     `db:"last_seen_at"`
		LastAuthAt time.Time     `db:"last_auth_at"`
		ExpiresAt  time.Time     `db:"expires_at"`
	}
	err := s.db.GetContext(ctx, &row, `
		SELECT user_id, identity_id, auth_method, csrf_token,
		       created_at, last_seen_at, last_auth_at, expires_at
		FROM sessions
		WHERE id = ?
	`, digest(plaintextID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query session: %w", err)
	}
	now := s.now()
	// Absolute cap: pinned at mint time via expires_at so a config change to Absolute doesn't retroactively extend or shorten existing
	// sessions, and Get's verdict matches CleanupExpired's (which also deletes by expires_at). The auth_method-derived pair below is only
	// consulted for the idle gate.
	if !row.ExpiresAt.After(now) {
		return nil, ErrNotFound
	}
	t := s.timeoutsFor(row.AuthMethod)
	// Idle cap: inactivity timeout sliding off last_seen_at.
	if now.Sub(row.LastSeenAt) >= t.Idle {
		return nil, ErrNotFound
	}
	var idPtr *int64
	if row.IdentityID.Valid {
		v := row.IdentityID.Int64
		idPtr = &v
	}
	return &Session{
		// Return the plaintext id the caller passed in so downstream code (e.g.
		// idPrefix for audit logs) can render a stable prefix for correlation.
		ID: plaintextID, UserID: row.UserID, IdentityID: idPtr, AuthMethod: row.AuthMethod,
		CSRFToken:  row.CSRFToken,
		CreatedAt:  row.CreatedAt,
		LastSeenAt: row.LastSeenAt,
		LastAuthAt: row.LastAuthAt,
		ExpiresAt:  row.ExpiresAt,
	}, nil
}

// Touch advances last_seen_at to NOW() if the cached value is older than
// touchThrottle (default 1 minute). Returns the resulting last_seen_at — the
// cached value when no UPDATE was needed, or NOW() when an UPDATE ran. Pass
// the cached LastSeenAt so a tight loop of Touch calls doesn't rewrite the row
// when it's already fresh — middleware uses sess.LastSeenAt as the cache.
//
// On UPDATE failure the cached value is returned with a wrapped error; callers
// SHOULD log + continue rather than fail the request. Idle expiry is enforced
// at Get time, so a missed Touch costs at most one minute of idle granularity.
func (s *Store) Touch(ctx context.Context, plaintextID []byte, cached time.Time) (time.Time, error) {
	if len(plaintextID) != IDLen {
		return cached, nil
	}
	now := s.now()
	if now.Sub(cached) < touchThrottle {
		return cached, nil
	}
	// Explicit UPDATE wins over the column's ON UPDATE CURRENT_TIMESTAMP — we
	// want the value the store's clock returned, not whatever MySQL sees.
	if _, err := s.db.ExecContext(ctx, `
		UPDATE sessions SET last_seen_at = ? WHERE id = ?
	`, now, digest(plaintextID)); err != nil {
		return cached, fmt.Errorf("touch session: %w", err)
	}
	return now, nil
}

// UpdateLastAuthAt stamps last_auth_at = NOW() on the matching session,
// resetting the freshness window. Called from every login site (initial mint,
// OIDC reauth callback dispatch, break-glass reauth POST). Also bumps
// last_seen_at since a successful authentication is by definition activity.
//
// Returns ErrNotFound when no row matches the digest.
func (s *Store) UpdateLastAuthAt(ctx context.Context, plaintextID []byte) error {
	if len(plaintextID) != IDLen {
		return ErrNotFound
	}
	now := s.now()
	res, err := s.db.ExecContext(ctx, `
		UPDATE sessions SET last_auth_at = ?, last_seen_at = ? WHERE id = ?
	`, now, now, digest(plaintextID))
	if err != nil {
		return fmt.Errorf("update last_auth_at: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// IsFresh reports whether the session's last_auth_at falls within the configured reauth window. The chokepoint reads it via
// Actor.SessionFresh to gate destructive actions.
func (s *Store) IsFresh(sess *Session) bool {
	if sess == nil {
		return false
	}
	return s.now().Sub(sess.LastAuthAt) < s.reauthWin
}

// ReauthWindow returns the configured freshness window. Exposed so the reauth
// handler + operator-facing copy share one source of truth for the value.
func (s *Store) ReauthWindow() time.Duration { return s.reauthWin }

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

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
