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
//
// Sessions are minted by the OIDC callback (server/identity/internal/oidc) and the break-glass FinishLogin / FinishSetup
// paths (server/identity/internal/breakglass); there is no password-based login surface. The Service surface covers session
// lifecycle (Logout, CleanupExpiredSessions, GetSession, MarkReauth), user lookup (GetUser, GetUserByEmail, UserExists),
// chokepoint actor loading (LoadActor, IsFresh), and the first-boot admin seed (SeedAdmin).
type Service interface {
	// Logout deletes the session identified by the cookie token. Idempotent: returns nil if the session is already gone, so logout under
	// network retry is safe.
	Logout(ctx context.Context, sessionToken []byte) error

	// GetSession resolves a cookie-borne session token to its session metadata. Used by the Session middleware on every authed request.
	// Returns ErrSessionNotFound for unknown or expired tokens.
	GetSession(ctx context.Context, sessionToken []byte) (*Session, error)

	// GetUser returns the user record for the given user id. Used by handlers that need user fields beyond the userID pinned on ctx (e.g.
	// handleGet renders {user.id, user.email}). Returns ErrUserNotFound for unknown ids.
	GetUser(ctx context.Context, userID int64) (User, error)

	// SeedAdmin creates the first admin user if no users exist, prints the generated password to w, and returns the user record +
	// plaintext password. Returns (zero User, "", ErrAlreadySeeded) if the table is non-empty so the caller can errors.Is to the
	// success-but-noop case.
	SeedAdmin(ctx context.Context, w io.Writer) (User, string, error)

	// UserExists reports whether the user id refers to a live user. Replaces the cross-context FK fk_alerts_updated_by that the
	// bounded-context split dropped: detection's alert-update handler calls UserExists before writing alerts.updated_by.
	UserExists(ctx context.Context, userID int64) (bool, error)

	// CleanupExpiredSessions deletes session rows whose expires_at is in the past. Returns the count removed. Called from the identity Run
	// loop on a fixed-interval ticker.
	CleanupExpiredSessions(ctx context.Context) (int64, error)

	// LoadActor builds the per-request actor for the AuthZ chokepoint.
	// Composes the user row (is_breakglass) with the caller's live
	// role bindings; both queries are indexed and run well under the
	// chokepoint's p99 latency budget.
	//
	// authMethod records how the session was authenticated
	// ('local_password' for break-glass, 'oidc' for SSO).
	// sessionFresh is the reauth-window flag (true when last_auth_at
	// is within the reauth window); the chokepoint's destructive-action
	// rules deny with reason="reauth_required" when the role grants the
	// action but sessionFresh is false.
	LoadActor(ctx context.Context, userID int64, authMethod string, sessionFresh bool) (*Actor, error)

	// UpdateLastAuthAt stamps the session's freshness timestamp to
	// NOW(), resetting the reauth window. Called from the break-glass
	// reauth POST endpoint after credential verification — the same
	// cookie keeps working with a refreshed timestamp, no new session
	// minted. Returns ErrSessionNotFound when no session matches the
	// token.
	//
	// OIDC reauth does NOT use this method: the OIDC callback always
	// mints a fresh session on a successful exchange (whose
	// Create-time last_auth_at is NOW() automatically). The previous
	// session is orphaned and reaped on its absolute expiry. Explicit
	// tradeoff to avoid threading session-continuity through the OIDC
	// state cookie; revisit if the orphan rate becomes a concern at
	// scale.
	UpdateLastAuthAt(ctx context.Context, sessionToken []byte) error

	// IsFresh reports whether the session's last_auth_at falls within the configured reauth window. The Session middleware reads it at
	// request time to populate Actor.SessionFresh. Returns false for a nil session.
	IsFresh(s *Session) bool

	// TouchSession advances the session's last_seen_at to NOW(), throttled so a tight-loop of authenticated requests collapses to one
	// DB write per ~minute. The Session middleware calls it on every authed request as the sliding-extension mechanism behind the
	// idle timeout. cachedLastSeen lets the store skip the UPDATE without a SELECT when the cached value is already fresh. Returns the
	// resulting last_seen_at — when the throttle skipped the UPDATE this is cachedLastSeen, otherwise the store clock at write time.
	// Caller should plumb the returned value back onto its cached *Session so a chain of Touches inside the same throttle window stays a
	// no-op against the updated cache. Errors are non-fatal — a missed touch costs at most the throttle window of idle granularity.
	TouchSession(ctx context.Context, sessionToken []byte, cachedLastSeen time.Time) (time.Time, error)
}
