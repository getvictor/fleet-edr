// Package authn ties HTTP credentials to identities. Three middlewares live here:
//
//   - HostToken wraps ingest + command-poll routes. It resolves the bearer token to a
//     host_id via the enrollment store, pins the host_id on the request context, and
//     attaches `edr.host_id` to the active OTel span.
//
//   - Session wraps UI + admin routes. It extracts the `edr_session` cookie, looks up
//     the row in the sessions table, and pins user_id + session_id + csrf_token onto
//     the request context. Phase 3 replaces the Phase 1 `AdminToken` stopgap.
//
//   - CSRF wraps the same UI + admin routes as Session and runs AFTER Session has
//     pinned the per-session CSRF token onto the context (i.e. Session is the outer
//     middleware; CSRF is applied to the inner handler). In Go's convention
//     `outer(inner(h))` runs the outer on the way in, so the correct composition is
//     `Session(CSRF(h))`. Reversing them yields csrf_misconfigured 500s on every
//     unsafe method. The middleware compares the `X-CSRF-Token` header against the
//     stored value on unsafe methods (POST, PUT, DELETE, PATCH) via
//     subtle.ConstantTimeCompare; safe methods (GET, HEAD, OPTIONS) pass through.
//
// Authentication failures return 401 + JSON body + `WWW-Authenticate: Bearer`. Verifier
// outages (DB down, unexpected errors) return 503 without WWW-Authenticate so an agent
// cannot misinterpret infrastructure failure as token revocation and burn its re-enroll
// throttle. CSRF failures return 403. All outcomes emit structured audit logs + span
// attributes for SigNoz.
package authn

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/enrollment"
	"github.com/fleetdm/edr/server/sessions"
)

// Shared base64url encoders. `rawURLEncoding` (no padding) is what we emit for session
// ids + CSRF tokens on the wire; `urlEncoding` (with padding) is accepted as a fallback
// when decoding so padding-normalising middleboxes don't lock users out.
var (
	rawURLEncoding = base64.RawURLEncoding
	urlEncoding    = base64.URLEncoding
)

// EncodeSessionID serialises the raw session id bytes into the on-wire cookie value.
// Exported so the session handler package can set Set-Cookie with the same encoding
// the Session middleware expects.
func EncodeSessionID(raw []byte) string { return rawURLEncoding.EncodeToString(raw) }

// DecodeSessionIDForTest is the reverse. Exported for downstream test packages that
// need to look up a session by cookie value via the sessions store directly. Production
// code should go through the Session middleware.
func DecodeSessionIDForTest(cookieValue string) ([]byte, error) {
	return decodeSessionCookie(cookieValue)
}

// ctxKey is an unexported context key type so callers have to go through HostIDFromContext.
type ctxKey int

const (
	ctxKeyHostID ctxKey = iota + 1
	ctxKeyUserID
	ctxKeySession
)

// SessionCookieName is the HTTP cookie name the UI uses for the session id. Exported so
// the session handler package (which sets + clears the cookie) stays consistent with
// this package's middleware (which reads it).
const SessionCookieName = "edr_session"

// CSRFHeaderName is the HTTP header the UI sends the per-session CSRF token in.
// Behaviorally it would work as "X-CSRF-Token" because HTTP header names are
// case-insensitive per RFC 7230 and net/http canonicalises lookups via
// http.CanonicalMIMEHeaderKey. We use the canonical form here so the
// canonicalheader linter stays happy without a per-file suppression; UI docs
// + JS emit "X-CSRF-Token" and the wire handles both equivalently.
const CSRFHeaderName = "X-Csrf-Token"

// HostIDFromContext returns the host_id pinned by the HostToken middleware. The second
// return value is false when the context was not wrapped (e.g. the caller bypassed middleware).
func HostIDFromContext(ctx context.Context) (string, bool) {
	v := ctx.Value(ctxKeyHostID)
	s, ok := v.(string)
	return s, ok && s != ""
}

// WithHostIDForTest returns a context with the host_id pinned. Exported for downstream test
// packages that want to exercise handlers directly (without going through the real middleware
// chain). Production code must not call this.
func WithHostIDForTest(ctx context.Context, hostID string) context.Context {
	return context.WithValue(ctx, ctxKeyHostID, hostID)
}

// HostToken returns a middleware that validates an agent's bearer token against the
// enrollment store. On success, the middleware pins the host_id onto the request context
// and the active span. On failure, it returns 401 with a typed reason.
func HostToken(store *enrollment.Store, logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			token, ok := extractBearer(r)
			if !ok {
				fail(ctx, w, logger, "missing_bearer")
				return
			}
			hostID, err := store.Verify(ctx, token)
			switch {
			case errors.Is(err, enrollment.ErrTokenMismatch):
				// The token length is always 43 for an issued token, so unknown + revoked both
				// surface as ErrTokenMismatch. We don't distinguish them here because doing so
				// would be an oracle for token-still-active probing. The admin endpoint is the
				// place to look up revocation state.
				fail(ctx, w, logger, "invalid_token")
				return
			case err != nil:
				// DB / internal errors must not look like a revocation to the agent — returning
				// 401 here would trip the re-enroll hook in the agent and burn its throttle
				// during infrastructure outages. Use 503 + no WWW-Authenticate instead.
				logger.ErrorContext(ctx, "authn verify", "err", err)
				failStatus(ctx, w, logger, http.StatusServiceUnavailable, "verifier_unavailable")
				return
			}
			trace.SpanFromContext(ctx).SetAttributes(attribute.String("edr.host_id", hostID))
			r = r.WithContext(context.WithValue(ctx, ctxKeyHostID, hostID))
			next.ServeHTTP(w, r)
		})
	}
}

// UserIDFromContext returns the user id pinned by the Session middleware. Second return
// is false when the context was not wrapped.
func UserIDFromContext(ctx context.Context) (int64, bool) {
	v := ctx.Value(ctxKeyUserID)
	n, ok := v.(int64)
	return n, ok && n > 0
}

// SessionFromContext returns the full session pinned by the Session middleware. Callers
// that only need the user id should use UserIDFromContext; those that also need the
// CSRF token (e.g. an endpoint that re-renders the login page) can read it from here.
func SessionFromContext(ctx context.Context) (*sessions.Session, bool) {
	v := ctx.Value(ctxKeySession)
	s, ok := v.(*sessions.Session)
	return s, ok && s != nil
}

// WithUserIDForTest pins a user id on the ctx. Exported so handler tests can bypass the
// Session middleware. Production code must not call this.
func WithUserIDForTest(ctx context.Context, userID int64) context.Context {
	return context.WithValue(ctx, ctxKeyUserID, userID)
}

// WithSessionForTest pins a full session on the ctx. Same test-only caveat as
// WithUserIDForTest.
func WithSessionForTest(ctx context.Context, s *sessions.Session) context.Context {
	return context.WithValue(ctx, ctxKeySession, s)
}

// Session returns a middleware that validates the `edr_session` cookie against the
// sessions store. On success the request context carries user_id + the full session
// (for downstream CSRF + handlers that log the actor). On failure it returns 401 with
// a typed reason that the UI's 401 handler maps to "redirect to login".
func Session(store *sessions.Store, logger *slog.Logger) func(http.Handler) http.Handler {
	if store == nil {
		panic("authn.Session: store must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			cookie, err := r.Cookie(SessionCookieName)
			if err != nil || cookie.Value == "" {
				fail(ctx, w, logger, "missing_session")
				return
			}
			raw, err := decodeSessionCookie(cookie.Value)
			if err != nil {
				fail(ctx, w, logger, "invalid_session")
				return
			}
			sess, err := store.Get(ctx, raw)
			switch {
			case errors.Is(err, sessions.ErrNotFound):
				// Covers both "cookie points at a deleted row" (logout happened elsewhere)
				// and "cookie points at an expired row". The UI collapses these to the
				// same "redirect to login" behaviour.
				fail(ctx, w, logger, "invalid_session")
				return
			case err != nil:
				logger.ErrorContext(ctx, "session lookup", "err", err)
				failStatus(ctx, w, logger, http.StatusServiceUnavailable, "session_store_unavailable")
				return
			}
			trace.SpanFromContext(ctx).SetAttributes(
				attribute.Int64("edr.user.id", sess.UserID),
				attribute.String("edr.auth.result", "ok"),
			)
			ctx = context.WithValue(ctx, ctxKeyUserID, sess.UserID)
			ctx = context.WithValue(ctx, ctxKeySession, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// CSRF returns a middleware that enforces per-session CSRF tokens on unsafe methods.
// Wire it INSIDE Session so Session runs first (outer middleware runs on the way in)
// and pins the session on ctx before CSRF reads it:
//
//	mux.Handle("PUT /api/v1/alerts/{id}", Session(store, logger)(CSRF(logger)(h)))
//
// Safe methods (GET/HEAD/OPTIONS) pass through without any CSRF check. Callers that
// expose a non-idempotent GET would be making a mistake regardless of auth.
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
			sess, ok := SessionFromContext(ctx)
			if !ok {
				// Middleware mis-wiring: CSRF without Session. Fail loud rather than
				// silently let the request through. 500 rather than 401 because the
				// problem is server-side, not the caller's credentials.
				logger.ErrorContext(ctx, "CSRF middleware invoked without Session on ctx")
				failStatus(ctx, w, logger, http.StatusInternalServerError, "csrf_misconfigured")
				return
			}
			presented := r.Header.Get(CSRFHeaderName)
			if presented == "" {
				failStatus(ctx, w, logger, http.StatusForbidden, "csrf_missing")
				return
			}
			got, err := decodeSessionCookie(presented)
			if err != nil || subtle.ConstantTimeCompare(got, sess.CSRFToken) != 1 {
				failStatus(ctx, w, logger, http.StatusForbidden, "csrf_mismatch")
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

// decodeSessionCookie is the shared base64url decoder for session ids + CSRF tokens. We
// accept both padded and raw-unpadded encodings because middlebox URL rewriters
// occasionally strip trailing `=` and we'd rather accept the slight ambiguity than lock
// customers out. Production UI always emits the raw-unpadded form.
func decodeSessionCookie(s string) ([]byte, error) {
	// Try raw-unpadded first (the form we emit).
	if b, err := rawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return urlEncoding.DecodeString(s)
}

// extractBearer returns the token portion of an "Authorization: Bearer <token>" header.
// Returns ("", false) for missing/malformed/empty-token headers.
func extractBearer(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) {
		return "", false
	}
	token := strings.TrimSpace(auth[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

type errBody struct {
	Error string `json:"error"`
}

func fail(ctx context.Context, w http.ResponseWriter, logger *slog.Logger, reason string) {
	failStatus(ctx, w, logger, http.StatusUnauthorized, reason)
}

// failStatus is the general failure writer. WWW-Authenticate is set only on 401 responses —
// sending it with a 5xx would encourage retry-with-new-credentials logic that cannot help
// when the real problem is a server-side outage.
func failStatus(ctx context.Context, w http.ResponseWriter, logger *slog.Logger, status int, reason string) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.String("edr.auth.result", "fail"),
		attribute.String("edr.auth.reason", reason),
	)
	logger.WarnContext(ctx, "authn failed", "edr.auth.reason", reason, "status", status)

	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errBody{Error: reason})
}
