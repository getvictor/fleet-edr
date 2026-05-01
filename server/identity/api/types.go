// Public types for the identity bounded context. See the package doc in doc.go.

package api

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// HTTP-protocol constants shared between the identity login handler (sets
// the cookie + reads the CSRF header) and the identity middleware (reads
// the cookie + validates the CSRF header). Other contexts that need to
// reason about these names (e.g. integration tests that craft requests
// directly) import them through this package.
const (
	// SessionCookieName is the HTTP cookie name carrying the operator session token.
	SessionCookieName = "edr_session"
	// CSRFHeaderName is the HTTP header carrying the per-session CSRF token on
	// unsafe methods. Stored as the canonical case (X-Csrf-Token) so the
	// canonicalheader linter passes; HTTP header names are case-insensitive
	// per RFC 7230 so clients can send X-CSRF-Token equivalently.
	CSRFHeaderName = "X-Csrf-Token"
)

// User is the operator-visible identity. The password hash + salt are
// intentionally excluded; they live only inside the internal users store
// so that an accidental %v / slog("user", u) cannot leak credentials.
type User struct {
	ID        int64     `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Session is the server-side session record without the bearer token.
// The plaintext token is the cookie value, returned only at Login (in
// LoginResult.SessionToken) and never persisted server-side. The DB
// stores SHA-256 of the token; sessions store does the digest internally.
//
// CSRFToken is exposed as raw bytes because the CSRF middleware compares
// it via constant-time compare against the decoded X-Csrf-Token header.
type Session struct {
	UserID     int64
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	CSRFToken  []byte
}

// LoginResult bundles everything the login HTTP handler needs to respond
// to a successful login. SessionToken is the raw plaintext token; the
// handler encodes it for the cookie value. CSRFToken is the raw token;
// the handler encodes it for the JSON body. Both are returned exactly
// once at Login -- the server never persists either in plaintext.
type LoginResult struct {
	User         User
	SessionToken []byte
	CSRFToken    []byte
	ExpiresAt    time.Time
}

// Error sentinels returned across the api boundary. Callers compare with
// errors.Is. Login error wrapping: ErrUserNotFound and ErrBadPassword both
// wrap ErrInvalidCredentials so the typical caller can errors.Is(err,
// ErrInvalidCredentials) for the 401 case while audit logging can
// distinguish "unknown email" from "wrong password" with a separate
// errors.Is against the more specific sentinel.
var (
	ErrInvalidCredentials = errors.New("identity: invalid credentials")
	ErrUserNotFound       = fmt.Errorf("identity: user not found: %w", ErrInvalidCredentials)
	ErrBadPassword        = fmt.Errorf("identity: password mismatch: %w", ErrInvalidCredentials)
	ErrSessionNotFound    = errors.New("identity: session not found or expired")
	ErrAlreadySeeded      = errors.New("identity: admin already seeded")
)

// ctxKey is unexported so ctx values can only be set via the With*
// helpers below, which is the only path we want.
type ctxKey int

const (
	ctxKeyUserID ctxKey = iota + 1
	ctxKeySession
)

// WithUserID returns a context with the user id pinned. Called by the
// Session middleware on every authed request; called directly by tests
// in any context that need to mint a synthetic authenticated context.
func WithUserID(ctx context.Context, userID int64) context.Context {
	return context.WithValue(ctx, ctxKeyUserID, userID)
}

// UserIDFromContext returns the user id pinned by Session middleware (or
// by tests via WithUserID). The second return is false when no user id
// is on ctx, so callers can distinguish "anonymous" from "user 0".
func UserIDFromContext(ctx context.Context) (int64, bool) {
	v := ctx.Value(ctxKeyUserID)
	n, ok := v.(int64)
	return n, ok && n > 0
}

// WithSession returns a context with the full session pinned.
func WithSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, ctxKeySession, s)
}

// SessionFromContext returns the session pinned by Session middleware.
func SessionFromContext(ctx context.Context) (*Session, bool) {
	v := ctx.Value(ctxKeySession)
	s, ok := v.(*Session)
	return s, ok && s != nil
}

// WithUserIDForTest is a backward-compat alias for WithUserID. Existing
// tests across the codebase use the ForTest naming; keep it working
// without forcing a rename in the same PR. New tests should prefer
// WithUserID.
func WithUserIDForTest(ctx context.Context, userID int64) context.Context {
	return WithUserID(ctx, userID)
}

// WithSessionForTest is a backward-compat alias for WithSession.
func WithSessionForTest(ctx context.Context, s *Session) context.Context {
	return WithSession(ctx, s)
}
