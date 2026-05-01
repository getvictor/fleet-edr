package middleware

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/attrkeys"
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
			cookie, err := r.Cookie(api.SessionCookieName)
			if err != nil || cookie.Value == "" {
				fail(ctx, w, logger, http.StatusUnauthorized, "missing_session")
				return
			}
			raw, err := api.DecodeToken(cookie.Value)
			if err != nil {
				fail(ctx, w, logger, http.StatusUnauthorized, "invalid_session")
				return
			}
			sess, err := svc.GetSession(ctx, raw)
			switch {
			case errors.Is(err, api.ErrSessionNotFound):
				// Covers both "cookie points at deleted row" (logout happened
				// elsewhere) and "cookie points at expired row". The UI maps
				// both to "redirect to login".
				fail(ctx, w, logger, http.StatusUnauthorized, "invalid_session")
				return
			case err != nil:
				logger.ErrorContext(ctx, "session lookup", "err", err)
				fail(ctx, w, logger, http.StatusServiceUnavailable, "session_store_unavailable")
				return
			}
			trace.SpanFromContext(ctx).SetAttributes(
				attribute.Int64(attrkeys.UserID, sess.UserID),
				attribute.String(attrkeys.AuthResult, "ok"),
			)
			ctx = api.WithUserID(ctx, sess.UserID)
			ctx = api.WithSession(ctx, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// CSRF returns the CSRF middleware. It expects to run AFTER Session has
// pinned the session on ctx (Session(CSRF(h)) pattern). Safe methods
// (GET, HEAD, OPTIONS) pass through without check; unsafe methods must
// present X-Csrf-Token matching the per-session token.
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
				// Middleware mis-wiring: CSRF without Session. Fail loud
				// with 500 because the problem is server-side, not the
				// caller's credentials.
				logger.ErrorContext(ctx, "CSRF middleware invoked without Session on ctx")
				fail(ctx, w, logger, http.StatusInternalServerError, "csrf_misconfigured")
				return
			}
			presented := r.Header.Get(api.CSRFHeaderName)
			if presented == "" {
				fail(ctx, w, logger, http.StatusForbidden, "csrf_missing")
				return
			}
			got, err := api.DecodeToken(presented)
			if err != nil || subtle.ConstantTimeCompare(got, sess.CSRFToken) != 1 {
				fail(ctx, w, logger, http.StatusForbidden, "csrf_mismatch")
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

// errBody is the JSON shape this middleware writes on auth/CSRF failures.
type errBody struct {
	Error string `json:"error"`
}

// fail writes a typed JSON error + audit log. WWW-Authenticate is set
// only on 401 responses; on 5xx we omit it so an agent can't misinterpret
// infrastructure failure as token revocation. Mirrors the authn package's
// error-writing behaviour exactly so the wire response shape is unchanged.
func fail(ctx context.Context, w http.ResponseWriter, logger *slog.Logger, status int, reason string) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.String(attrkeys.AuthResult, "fail"),
		attribute.String(attrkeys.AuthReason, reason),
	)
	logger.WarnContext(ctx, "authn failed", attrkeys.AuthReason, reason, "status", status)

	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errBody{Error: reason})
}
