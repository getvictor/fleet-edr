package api

import (
	"context"
	"io"
	"time"
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

	// LoadActor builds the per-request actor for the AuthZ chokepoint.
	// Composes the user row (tenant_id, is_breakglass) with the
	// caller's live role bindings; both queries are indexed and run
	// well under the chokepoint's p99 latency budget.
	//
	// authMethod records how the session was authenticated
	// ('local_password' for break-glass, 'oidc' for SSO).
	// sessionFresh is the Phase 5 reauth-window flag (true when
	// last_auth_at is within the reauth window); the chokepoint's
	// destructive-action rules deny with reason="reauth_required"
	// when the role grants the action but sessionFresh is false.
	LoadActor(ctx context.Context, userID int64, authMethod string, sessionFresh bool) (*Actor, error)

	// UpdateLastAuthAt stamps the session's freshness timestamp to
	// NOW(), resetting the reauth window. Called from the OIDC
	// callback when handling a reauth=1 dispatch (re-uses the
	// existing session row instead of minting a new one) and from
	// the break-glass reauth POST endpoint after credential
	// verification. Returns ErrSessionNotFound when no session
	// matches the token.
	UpdateLastAuthAt(ctx context.Context, sessionToken []byte) error

	// IsFresh reports whether the session's last_auth_at falls
	// within the configured reauth window. The Session middleware
	// reads it at request time to populate Actor.SessionFresh.
	// Returns false for a nil session.
	IsFresh(s *Session) bool

	// TouchSession advances the session's last_seen_at to NOW(),
	// throttled so a tight-loop of authenticated requests collapses
	// to one DB write per ~minute. The Session middleware calls it
	// on every authed request as the sliding-extension mechanism
	// behind the idle timeout. cachedLastSeen lets the store skip
	// the UPDATE without a SELECT when the cached value is already
	// fresh. Errors are non-fatal — a missed touch costs at most
	// the throttle window of idle granularity.
	TouchSession(ctx context.Context, sessionToken []byte, cachedLastSeen time.Time) error
}
