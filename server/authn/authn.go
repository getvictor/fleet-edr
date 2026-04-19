// Package authn ties the HTTP Authorization header to the identity established at enroll
// time. Two middlewares live here:
//
//   - HostToken wraps ingest + command-poll routes. It resolves the bearer token to a
//     host_id via the enrollment store, pins the host_id on the request context, and
//     attaches `edr.host_id` to the active OTel span.
//
//   - AdminToken wraps UI + admin routes. It compares the bearer token against the
//     single-value EDR_ADMIN_TOKEN (stopgap until Phase 3 replaces with sessions).
//
// Both middlewares respond with 401 + a machine-readable JSON body and the standard
// `WWW-Authenticate: Bearer error="invalid_token"` header on failure, and emit structured
// audit logs + span attributes the operator can filter on in SigNoz.
package authn

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/enrollment"
)

// ctxKey is an unexported context key type so callers have to go through HostIDFromContext.
type ctxKey int

const (
	ctxKeyHostID ctxKey = iota + 1
)

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
				logger.ErrorContext(ctx, "authn verify", "err", err)
				fail(ctx, w, logger, "internal")
				return
			}
			trace.SpanFromContext(ctx).SetAttributes(attribute.String("edr.host_id", hostID))
			r = r.WithContext(context.WithValue(ctx, ctxKeyHostID, hostID))
			next.ServeHTTP(w, r)
		})
	}
}

// AdminToken returns a middleware that gates UI + admin routes behind a shared admin token.
// Phase 3 replaces this with session cookies + a proper user table; until then the admin
// token is the stopgap.
func AdminToken(adminToken string, logger *slog.Logger) func(http.Handler) http.Handler {
	if adminToken == "" {
		panic("authn.AdminToken: adminToken must not be empty")
	}
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
			if subtle.ConstantTimeCompare([]byte(token), []byte(adminToken)) != 1 {
				fail(ctx, w, logger, "invalid_token")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
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
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.String("edr.auth.result", "fail"),
		attribute.String("edr.auth.reason", reason),
	)
	logger.WarnContext(ctx, "authn failed", "edr.auth.reason", reason)

	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(errBody{Error: reason})
}
