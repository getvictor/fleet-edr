package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/seed"
	"github.com/fleetdm/edr/server/identity/internal/sessions"
	"github.com/fleetdm/edr/server/identity/internal/users"
)

// service implements api.Service by composing the users + sessions stores
// and delegating to the seed package for first-boot setup.
type service struct {
	users    *users.Store
	sessions *sessions.Store
	logger   *slog.Logger
}

// New constructs a Service. The Service is the cross-context entry point
// for the identity bounded context; the login HTTP handler and the
// session/CSRF middleware also call into it for business logic so the
// orchestration is in one place.
//
// All inputs are required to be non-nil; bootstrap.New is the only caller
// and provides them via Deps. A nil-defensive branch here would be dead
// code, so we trust the caller.
func New(u *users.Store, s *sessions.Store, logger *slog.Logger) api.Service {
	return &service{users: u, sessions: s, logger: logger}
}

func (s *service) Login(ctx context.Context, email, password string) (api.LoginResult, error) {
	u, err := s.users.VerifyPassword(ctx, email, password)
	switch {
	case errors.Is(err, users.ErrNotFound):
		return api.LoginResult{}, api.ErrUserNotFound
	case errors.Is(err, users.ErrBadPassword):
		return api.LoginResult{}, api.ErrBadPassword
	case err != nil:
		return api.LoginResult{}, fmt.Errorf("verify password: %w", err)
	}
	sess, err := s.sessions.Create(ctx, u.ID)
	if err != nil {
		return api.LoginResult{}, fmt.Errorf("create session: %w", err)
	}
	return api.LoginResult{
		User:         toAPIUser(u),
		SessionToken: sess.ID,
		CSRFToken:    sess.CSRFToken,
		ExpiresAt:    sess.ExpiresAt,
	}, nil
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
	u, pw, err := seed.Admin(ctx, s.users, s.logger, w)
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

// toAPIUser converts the internal users.User row into the operator-visible
// api.User. Skipping the password hash is the whole point: the api type
// has no slot for it. Caller guarantees u is non-nil (every callsite
// already early-returns on error before reaching this).
func toAPIUser(u *users.User) api.User {
	return api.User{
		ID:        u.ID,
		Email:     u.Email,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}
}

// toAPISession converts the internal sessions.Session row to the api.Session
// shape. The plaintext ID stays internal; the api type carries only what
// callers (middleware + cross-context tests) legitimately need to read.
// Caller guarantees s is non-nil.
func toAPISession(s *sessions.Session) *api.Session {
	return &api.Session{
		UserID:     s.UserID,
		CreatedAt:  s.CreatedAt,
		LastSeenAt: s.LastSeenAt,
		ExpiresAt:  s.ExpiresAt,
		CSRFToken:  s.CSRFToken,
	}
}
