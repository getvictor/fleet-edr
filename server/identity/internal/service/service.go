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
	logger   *slog.Logger
}

// New constructs a Service. The Service is the cross-context entry point
// for the identity bounded context; the login HTTP handler, the
// session/CSRF middleware, and the AuthZ engine also call into it for
// business logic so the orchestration is in one place.
//
// All inputs are required to be non-nil; bootstrap.New is the only caller
// and provides them via Deps. A nil-defensive branch here would be dead
// code, so we trust the caller.
func New(u *users.Store, s *sessions.Store, r *rbac.Store, logger *slog.Logger) api.Service {
	return &service{users: u, sessions: s, rbac: r, logger: logger}
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
	bindings, err := s.rbac.ListLiveBindings(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("load actor bindings: %w", err)
	}
	return &api.Actor{
		UserID:       u.ID,
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
