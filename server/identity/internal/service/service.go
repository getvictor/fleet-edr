package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/rbac"
	"github.com/fleetdm/edr/server/identity/internal/seed"
	"github.com/fleetdm/edr/server/identity/internal/sessions"
	"github.com/fleetdm/edr/server/identity/internal/users"
)

// service implements api.Service by composing the users + sessions stores and delegating to the seed package for first-boot setup.
// rbac is the wave-1 role-binding read store the AuthZ chokepoint reaches through.
type service struct {
	users    *users.Store
	sessions *sessions.Store
	rbac     *rbac.Store
	saNames  serviceAccountNamer
	logger   *slog.Logger
}

// serviceAccountNamer is the subset of the service-account store the principal-label resolver needs (svc_<id> -> name). An interface
// keeps service.New decoupled from the full SA store and lets tests inject a fake.
type serviceAccountNamer interface {
	NameByID(ctx context.Context, id int64) (string, error)
}

// New constructs a Service. The Service is the cross-context entry point
// for the identity bounded context; the login HTTP handler, the
// session/CSRF middleware, and the AuthZ engine also call into it for
// business logic so the orchestration is in one place.
//
// u, s, r, and logger are required to be non-nil; bootstrap.New is the production caller and provides them via Deps, so a
// nil-defensive branch here would be dead code and we trust the caller. saNames is optional: when nil, PrincipalLabel cannot resolve a
// service-account name and returns "" for svc_<id> ids (tests that don't exercise that path pass nil).
func New(u *users.Store, s *sessions.Store, r *rbac.Store, saNames serviceAccountNamer, logger *slog.Logger) api.Service {
	return &service{users: u, sessions: s, rbac: r, saNames: saNames, logger: logger}
}

// PrincipalLabel resolves a principal id to its current display label by dispatching on the id prefix: a user to its live email, a
// service account to its live name, the system principal to "system". An unrecognized id yields "". See ADR-0017.
func (s *service) PrincipalLabel(ctx context.Context, principalID string) (string, error) {
	typ, ok := api.PrincipalTypeForID(principalID)
	if !ok {
		return "", nil
	}
	switch typ {
	case api.PrincipalSystem:
		return "system", nil
	case api.PrincipalUser:
		uid, ok := (api.PrincipalRef{ID: principalID}).UserID()
		if !ok {
			return "", nil
		}
		u, err := s.GetUser(ctx, uid)
		if err != nil {
			return "", err
		}
		return u.Email, nil
	case api.PrincipalServiceAccount:
		said, ok := (api.PrincipalRef{ID: principalID}).ServiceAccountID()
		if !ok || s.saNames == nil {
			return "", nil
		}
		return s.saNames.NameByID(ctx, said)
	}
	// PrincipalTypeForID returned ok=true, so typ is one of the three handled cases above; this terminal is unreachable today. It is
	// not a silent empty default: PrincipalType is a string type that could gain a member (an agent principal is deferred in ADR-0017),
	// and a fail-loud error here forces this resolver to be updated when that happens rather than silently mislabeling the new type.
	return "", fmt.Errorf("identity: unhandled principal type %q for principal %q", typ, principalID)
}

func (s *service) Logout(ctx context.Context, sessionToken []byte) error {
	if len(sessionToken) == 0 {
		return nil
	}
	if err := s.sessions.Delete(ctx, sessionToken); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (s *service) GetSession(ctx context.Context, sessionToken []byte) (*api.Session, error) {
	sess, err := s.sessions.Get(ctx, sessionToken)
	if errors.Is(err, sessions.ErrNotFound) {
		return nil, api.ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}
	return toAPISession(sess), nil
}

func (s *service) GetUser(ctx context.Context, userID int64) (api.User, error) {
	u, err := s.users.Get(ctx, userID)
	if errors.Is(err, users.ErrNotFound) {
		return api.User{}, api.ErrUserNotFound
	}
	if err != nil {
		return api.User{}, fmt.Errorf("get user: %w", err)
	}
	return toAPIUser(u), nil
}

func (s *service) SeedAdmin(ctx context.Context, w io.Writer) (api.User, string, error) {
	u, pw, err := seed.Admin(ctx, s.users, s.rbac, s.logger, w)
	if err != nil {
		return api.User{}, "", err
	}
	if u == nil {
		return api.User{}, "", api.ErrAlreadySeeded
	}
	return toAPIUser(u), pw, nil
}

func (s *service) UserExists(ctx context.Context, userID int64) (bool, error) {
	if userID <= 0 {
		return false, nil
	}
	_, err := s.users.Get(ctx, userID)
	switch {
	case errors.Is(err, users.ErrNotFound):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("user exists check: %w", err)
	}
	return true, nil
}

func (s *service) CleanupExpiredSessions(ctx context.Context) (int64, error) {
	return s.sessions.CleanupExpired(ctx)
}

// LoadActor builds the per-request actor for the AuthZ chokepoint.
// Two queries: one for users (already on the call path of every login
// today, so the row is hot in MySQL's buffer pool) and one for the
// caller's live role bindings. Returns ErrUserNotFound if the user
// row has been deleted out from under a still-valid session: the
// caller (session middleware) maps it to a 401 + cookie clear.
//
// sessionFresh is the reauth-window flag the middleware computes from
// sess.LastAuthAt; the chokepoint's destructive-action rules read it
// via Actor.SessionFresh.
func (s *service) LoadActor(ctx context.Context, userID int64, authMethod string, sessionFresh bool) (*api.Actor, error) {
	u, err := s.users.Get(ctx, userID)
	if errors.Is(err, users.ErrNotFound) {
		return nil, api.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load actor user %d: %w", userID, err)
	}
	// A disabled account is locked out of every authed request, even under an otherwise-valid session: the admin user-management
	// surface sets users.status, and this per-request check is what makes "disable" actually block access (#135).
	if u.Status == "disabled" {
		return nil, api.ErrUserDisabled
	}
	bindings, err := s.rbac.ListLiveBindings(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("load actor bindings: %w", err)
	}
	return &api.Actor{
		Principal:    api.UserPrincipal(u.ID, u.Email),
		IsBreakglass: u.IsBreakglass,
		AuthMethod:   authMethod,
		Roles:        bindings,
		SessionFresh: sessionFresh,
	}, nil
}

// UpdateLastAuthAt stamps the session's freshness window. Called from the OIDC callback when handling a reauth=1 dispatch and from the
// break-glass reauth POST endpoint. Returns ErrSessionNotFound when no row matches the digest.
func (s *service) UpdateLastAuthAt(ctx context.Context, sessionToken []byte) error {
	if err := s.sessions.UpdateLastAuthAt(ctx, sessionToken); err != nil {
		if errors.Is(err, sessions.ErrNotFound) {
			return api.ErrSessionNotFound
		}
		return fmt.Errorf("update last_auth_at: %w", err)
	}
	return nil
}

// IsFresh reports whether sess.LastAuthAt falls within the configured reauth window. Pass-through to the sessions store; lifted to the
// public Service surface so middleware can call it through the api boundary without importing internal/sessions.
func (s *service) IsFresh(sess *api.Session) bool {
	if sess == nil {
		return false
	}
	// Reconstruct a sessions.Session shell with LastAuthAt: that's
	// the only field the store's IsFresh inspects.
	return s.sessions.IsFresh(&sessions.Session{LastAuthAt: sess.LastAuthAt})
}

// TouchSession advances the session's last_seen_at if the cached value is older than the store's throttle window. Wraps
// sessions.Store.Touch. Returns the resulting last_seen_at (cachedLastSeen when the throttle skipped, otherwise NOW()) so the
// middleware can refresh its cached *Session. Without that, a long-running request that touches the row mid-flight would hand the
// next request a stale cache and force another write inside the throttle window. Errors are returned; middleware logs + continues
// since a missed touch costs at most one minute of idle granularity.
func (s *service) TouchSession(ctx context.Context, sessionToken []byte, cachedLastSeen time.Time) (time.Time, error) {
	t, err := s.sessions.Touch(ctx, sessionToken, cachedLastSeen)
	if err != nil {
		return cachedLastSeen, fmt.Errorf("touch session: %w", err)
	}
	return t, nil
}

// toAPIUser converts the internal users.User row into the operator-visible api.User. Skipping the password hash is the whole point:
// the api type has no slot for it. Caller guarantees u is non-nil (every callsite already early-returns on error before reaching
// this).
func toAPIUser(u *users.User) api.User {
	return api.User{
		ID:        u.ID,
		Email:     u.Email,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}
}

// toAPISession converts the internal sessions.Session row to the api.Session shape. The plaintext ID stays internal; the
// api type carries only what callers (middleware + cross-context tests) legitimately need to read. Caller guarantees s is
// non-nil; this helper is a value-copy with field renames, no validation. AuthMethod is passed through verbatim because
// sessions.Store.Create is the single INSERT site and normalises "" to "local_password" before the row hits the DB; the
// MySQL schema also pins NOT NULL DEFAULT 'local_password' as a belt-and-braces second invariant.
func toAPISession(s *sessions.Session) *api.Session {
	return &api.Session{
		UserID:     s.UserID,
		IdentityID: s.IdentityID,
		AuthMethod: s.AuthMethod,
		CreatedAt:  s.CreatedAt,
		LastSeenAt: s.LastSeenAt,
		LastAuthAt: s.LastAuthAt,
		ExpiresAt:  s.ExpiresAt,
		CSRFToken:  s.CSRFToken,
	}
}
