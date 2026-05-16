// Public types for the identity bounded context. See the package doc in doc.go.

package api

import (
	"context"
	"errors"
	"time"
)

// HTTP-protocol constants shared between the identity login handler (sets the cookie + reads the CSRF header) and the identity
// middleware (reads the cookie + validates the CSRF header). Other contexts that need to reason about these names (e.g. integration
// tests that craft requests directly) import them through this package.
const (
	// SessionCookieName is the HTTP cookie name carrying the operator session token.
	SessionCookieName = "edr_session"
	// CSRFHeaderName is the HTTP header carrying the per-session CSRF token on unsafe methods. Stored as the canonical case (X-Csrf-Token)
	// so the canonicalheader linter passes; HTTP header names are case-insensitive per RFC 7230 so clients can send X-CSRF-Token
	// equivalently.
	CSRFHeaderName = "X-Csrf-Token"
)

// User is the operator-visible identity. The password hash + salt are intentionally excluded; they live only inside the internal users
// store so that an accidental %v / slog("user", u) cannot leak credentials.
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
//
// AuthMethod records how the session was minted. Phase 4 unhardcodes
// the wave-1 placeholder so the chokepoint's actor.AuthMethod field
// reflects ground truth ("local_password" for break-glass /
// password-authenticated sessions, "oidc" for IdP-authenticated
// ones). IdentityID FKs into the identities table; nil for legacy
// password rows that pre-date Phase 4.
type Session struct {
	UserID     int64
	IdentityID *int64
	AuthMethod string
	CreatedAt  time.Time
	LastSeenAt time.Time
	// LastAuthAt records the most recent authentication event for this session — initial login or a successful reauth (Phase 5).
	// The chokepoint reads it through Service.LoadActor to decide whether the actor is "fresh enough" to perform destructive actions (host
	// commands, critical alert resolves) without re-prompting.
	LastAuthAt time.Time
	ExpiresAt  time.Time
	CSRFToken  []byte
}

// Error sentinels returned across the api boundary. Callers compare with
// errors.Is.
//
// Phase 5b retired the password-based Login method, so the wrap chain
// that used to thread ErrUserNotFound + ErrBadPassword through a parent
// ErrInvalidCredentials is gone. ErrUserNotFound remains because the
// session middleware reads it (a deleted user under a still-valid
// session manifests as ErrUserNotFound, mapped to invalid_session in
// the wire response).
var (
	ErrUserNotFound    = errors.New("identity: user not found")
	ErrSessionNotFound = errors.New("identity: session not found or expired")
	ErrAlreadySeeded   = errors.New("identity: admin already seeded")
)

// ctxKey is unexported so ctx values can only be set via the With*
// helpers below, which is the only path we want.
type ctxKey int

const (
	ctxKeyUserID ctxKey = iota + 1
	ctxKeySession
)

// WithUserID returns a context with the user id pinned. Called by the Session middleware on every authed request; called directly by
// tests in any context that need to mint a synthetic authenticated context.
func WithUserID(ctx context.Context, userID int64) context.Context {
	return context.WithValue(ctx, ctxKeyUserID, userID)
}

// UserIDFromContext returns the user id pinned by Session middleware (or by tests via WithUserID). The second return is false when no
// user id is on ctx, so callers can distinguish "anonymous" from "user 0".
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

// WithUserIDForTest is a backward-compat alias for WithUserID. Existing tests across the codebase use the ForTest naming; keep it
// working without forcing a rename in the same PR. New tests should prefer WithUserID.
func WithUserIDForTest(ctx context.Context, userID int64) context.Context {
	return WithUserID(ctx, userID)
}

// WithSessionForTest is a backward-compat alias for WithSession.
func WithSessionForTest(ctx context.Context, s *Session) context.Context {
	return WithSession(ctx, s)
}

// ----- User-management wave-1 read shapes -------------------------------------------
//
// The next two types describe the wave-1 user-management surface
// (roles, role-bindings) at the public boundary. This change ships the
// schema + seeds; the AuthZ interface that consumes RoleBinding (along
// with its Action constants) and the user-management writers are
// intentionally absent and land in follow-up changes. Keeping the read
// shapes here means the follow-up that introduces the chokepoint can
// wire it up without churning api/.

// Role is the operator-visible RBAC role. Five rows are seeded as builtin (super_admin, admin, senior_analyst, analyst, auditor);
// the admin API refuses to delete any row whose IsBuiltin is true. The permissions a role grants are NOT persisted on this row -- they
// live in the OPA / Rego policy bundle the Phase-2 AuthZ engine evaluates against.
type Role struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"display_name"`
	Description string    `json:"description,omitempty"`
	IsBuiltin   bool      `json:"is_builtin"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RoleBindingScopeType enumerates the scope a role binding applies at. The product is a single-instance deployment, so wave 1 honours
// only `global`, which means "deployment-wide". Bindings with other scope types MAY be persisted (the column is wave-2-ready) but the
// future chokepoint will deny them with reason `scope_not_yet_supported` until the host_group + host resolver ships.
type RoleBindingScopeType string

const (
	// RoleBindingScopeGlobal grants the role deployment-wide. The column reserves the enum values so adding host_group + host scopes later
	// does not require a schema migration.
	RoleBindingScopeGlobal RoleBindingScopeType = "global"
	// RoleBindingScopeHostGroup grants the role only against hosts in
	// the binding's host group. Reserved for wave 2.
	RoleBindingScopeHostGroup RoleBindingScopeType = "host_group"
	// RoleBindingScopeHost grants the role only against the binding's
	// single host. Reserved for wave 2.
	RoleBindingScopeHost RoleBindingScopeType = "host"
)

// RoleBindingScopeWildcard is the canonical scope_id for a deployment-wide binding. The `global` scope type ignores the literal value;
// we persist `*` so a `(scope_type, scope_id)` query always returns a well-formed pair.
const RoleBindingScopeWildcard = "*"

// RoleBinding binds a user to a role at a scope. The future AuthZ engine will read these to evaluate Allow(actor, action, resource).
// ExpiresAt is nullable; the evaluator treats an expired binding as if it did not exist on the request path.
type RoleBinding struct {
	ID        int64                `json:"id"`
	UserID    int64                `json:"user_id"`
	RoleID    string               `json:"role_id"`
	ScopeType RoleBindingScopeType `json:"scope_type"`
	ScopeID   string               `json:"scope_id"`
	ExpiresAt *time.Time           `json:"expires_at,omitempty"`
	CreatedAt time.Time            `json:"created_at"`
}
