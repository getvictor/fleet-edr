package api

import (
	"context"
	"io"
)

// Service is the identity bounded context's full business surface.
// Cross-context callers (today: detection's alert-update handler
// calls UserExists) and the identity HTTP handlers consume Service
// through this api package, never through the internal implementation.
//
// Implementation lives in server/identity/internal/service.
type Service interface {
	// Login verifies the credentials and creates a session. Returns
	// ErrUserNotFound (wraps ErrInvalidCredentials) for unknown email
	// and ErrBadPassword (also wraps ErrInvalidCredentials) for wrong
	// password; callers that want a single 401 response use
	// errors.Is(err, ErrInvalidCredentials). Both paths spend the same
	// argon2 cost so login latency cannot be used to enumerate emails.
	Login(ctx context.Context, email, password string) (LoginResult, error)

	// Logout deletes the session identified by the cookie token. Idempotent:
	// returns nil if the session is already gone, so logout under network
	// retry is safe.
	Logout(ctx context.Context, sessionToken []byte) error

	// GetSession resolves a cookie-borne session token to its session
	// metadata. Used by the Session middleware on every authed request.
	// Returns ErrSessionNotFound for unknown or expired tokens.
	GetSession(ctx context.Context, sessionToken []byte) (*Session, error)

	// GetUser returns the user record for the given user id. Used by
	// handlers that need user fields beyond the userID pinned on ctx
	// (e.g. handleGet renders {user.id, user.email}). Returns
	// ErrUserNotFound for unknown ids.
	GetUser(ctx context.Context, userID int64) (User, error)

	// SeedAdmin creates the first admin user if no users exist, prints the
	// generated password to w, and returns the user record + plaintext
	// password. Returns (zero User, "", ErrAlreadySeeded) if the table is
	// non-empty so the caller can errors.Is to the success-but-noop case.
	SeedAdmin(ctx context.Context, w io.Writer) (User, string, error)

	// UserExists reports whether the user id refers to a live user.
	// Replaces the cross-context FK fk_alerts_updated_by that the
	// bounded-context split dropped: detection's alert-update handler
	// calls UserExists before writing alerts.updated_by.
	UserExists(ctx context.Context, userID int64) (bool, error)

	// CleanupExpiredSessions deletes session rows whose expires_at is in
	// the past. Returns the count removed. Called from the identity Run
	// loop on a fixed-interval ticker.
	CleanupExpiredSessions(ctx context.Context) (int64, error)
}
