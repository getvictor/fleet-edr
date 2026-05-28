package middleware

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/identity/api"
)

// Session returns the operator-session middleware. It reads the session
// cookie, decodes it, calls the identity service to resolve it, and pins
// userID + session on the request context. On unknown / expired tokens
// it returns 401 with reason invalid_session; on infrastructure failure
// it returns 503 (so the UI's 401 handler doesn't redirect-loop on a
// transient outage).
//
// Wire as Session(CSRF(handler)) so Session pins the session on ctx
// before CSRF reads it. Reversing yields a 500.
func Session(svc api.Service, logger *slog.Logger) func(http.Handler) http.Handler {
	if svc == nil {
		panic("identity middleware: Service must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			sess, rawToken, ok := resolveSession(ctx, w, r, svc, logger)
			if !ok {
				return
			}
			actor, ok := resolveActor(ctx, w, svc, logger, sess)
			if !ok {
				return
			}
			trace.SpanFromContext(ctx).SetAttributes(
				attribute.Int64(attrkeys.UserID, sess.UserID),
				attribute.String(attrkeys.AuthResult, "ok"),
			)
			ctx = api.WithUserID(ctx, sess.UserID)
			ctx = api.WithSession(ctx, sess)
			ctx = api.WithActor(ctx, actor)
			next.ServeHTTP(w, r.WithContext(ctx))
			// Sliding-extension: stamp last_seen_at after the handler returns so the request itself isn't blocked
			// on the write. TouchSession is throttled internally — most calls are a no-op against the cached LastSeenAt.
			// The returned value is plumbed back onto sess so a touch that DID write updates the cache for downstream
			// code-paths that hold the session reference (e.g. an audit emit reading sess.LastSeenAt). Errors are logged +
			// dropped; idle granularity tolerates a missed touch.
			if newLastSeen, err := svc.TouchSession(ctx, rawToken, sess.LastSeenAt); err != nil {
				logger.WarnContext(ctx, "touch session", "err", err)
			} else {
				sess.LastSeenAt = newLastSeen
			}
		})
	}
}

// resolveSession reads the cookie, decodes the token, and resolves
// the session row through the service. On any failure it writes the
// auth-failure response and returns ok=false; the caller short-circuits.
//
// The raw plaintext token is returned alongside the session so the
// caller can pass it to write-side service methods (TouchSession,
// UpdateLastAuthAt) without re-reading the cookie. api.Session
// deliberately does not carry the plaintext.
func resolveSession(
	ctx context.Context, w http.ResponseWriter, r *http.Request,
	svc api.Service, logger *slog.Logger,
) (*api.Session, []byte, bool) {
	cookie, err := r.Cookie(api.SessionCookieName)
	if err != nil || cookie.Value == "" {
		httpserver.WriteCookieAuthFailure(ctx, w, logger, http.StatusUnauthorized, "missing_session")
		return nil, nil, false
	}
	raw, err := api.DecodeToken(cookie.Value)
	if err != nil {
		httpserver.WriteCookieAuthFailure(ctx, w, logger, http.StatusUnauthorized, "invalid_session")
		return nil, nil, false
	}
	sess, err := svc.GetSession(ctx, raw)
	switch {
	case errors.Is(err, api.ErrSessionNotFound):
		// Covers both "cookie points at deleted row" (logout happened elsewhere) and "cookie points at expired row". The UI maps both to
		// "redirect to login".
		httpserver.WriteCookieAuthFailure(ctx, w, logger, http.StatusUnauthorized, "invalid_session")
		return nil, nil, false
	case err != nil:
		logger.ErrorContext(ctx, "session lookup", "err", err)
		httpserver.WriteCookieAuthFailure(ctx, w, logger, http.StatusServiceUnavailable, "session_store_unavailable")
		return nil, nil, false
	}
	return sess, raw, true
}

// resolveActor builds the per-request actor (user row + live role bindings). A user-row deletion under a still-valid session manifests
// as ErrUserNotFound; we treat it as an invalid session. authMethod reads the value the session was minted with; legacy sessions
// inserted before the column existed default to "local_password".
func resolveActor(
	ctx context.Context, w http.ResponseWriter,
	svc api.Service, logger *slog.Logger, sess *api.Session,
) (*api.Actor, bool) {
	authMethod := sess.AuthMethod
	if authMethod == "" {
		authMethod = "local_password"
	}
	// Actor.SessionFresh is computed from the session's last_auth_at and the configured reauth window. The chokepoint reads it
	// via input.actor.session_fresh to gate destructive actions; everywhere else the value is informational.
	actor, err := svc.LoadActor(ctx, sess.UserID, authMethod, svc.IsFresh(sess))
	switch {
	case errors.Is(err, api.ErrUserNotFound):
		httpserver.WriteCookieAuthFailure(ctx, w, logger, http.StatusUnauthorized, "invalid_session")
		return nil, false
	case err != nil:
		// LoadActor failure can come from the users store, the rbac store, or a future identity-context dependency.
		// "session_store_unavailable" would be misleading here; "identity_store_unavailable" matches the failure surface so dashboards /
		// runbooks point at the right thing.
		logger.ErrorContext(ctx, "actor build", "err", err)
		httpserver.WriteCookieAuthFailure(ctx, w, logger, http.StatusServiceUnavailable, "identity_store_unavailable")
		return nil, false
	}
	return actor, true
}

// CSRF returns the CSRF middleware. It expects to run AFTER Session has pinned the session on ctx (Session(CSRF(h)) pattern). Safe
// methods (GET, HEAD, OPTIONS) pass through without check; unsafe methods must present X-Csrf-Token matching the per-session token.
func CSRF(logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isSafeMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			ctx := r.Context()
			sess, ok := api.SessionFromContext(ctx)
			if !ok {
				// Middleware mis-wiring: CSRF without Session. Fail loud with 500 because the problem is server-side,
				// not the caller's credentials.
				logger.ErrorContext(ctx, "CSRF middleware invoked without Session on ctx")
				httpserver.WriteCookieAuthFailure(ctx, w, logger, http.StatusInternalServerError, "csrf_misconfigured")
				return
			}
			presented := r.Header.Get(api.CSRFHeaderName)
			if presented == "" {
				httpserver.WriteCookieAuthFailure(ctx, w, logger, http.StatusForbidden, "csrf_missing")
				return
			}
			got, err := api.DecodeToken(presented)
			if err != nil || subtle.ConstantTimeCompare(got, sess.CSRFToken) != 1 {
				httpserver.WriteCookieAuthFailure(ctx, w, logger, http.StatusForbidden, "csrf_mismatch")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isSafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}
