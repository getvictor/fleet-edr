// Package authn ties HTTP credentials to the agent's host identity.
//
// HostToken wraps ingest + command-poll routes. It resolves the bearer
// token to a host_id via the enrollment store, pins the host_id on the
// request context, and attaches edr.host_id to the active OTel span.
//
// Authentication failures return 401 + JSON body + `WWW-Authenticate:
// Bearer`. Verifier outages (DB down, unexpected errors) return 503
// without WWW-Authenticate so an agent cannot misinterpret infrastructure
// failure as token revocation and burn its re-enroll throttle.
//
// Operator-session middleware (Session, CSRF) lives in
// server/identity/internal/middleware/ as part of the identity bounded
// context. This package keeps only the agent-facing host-token surface;
// phase 2 of the modular-monolith migration moves it under
// server/endpoint/internal/middleware/.
package authn

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/enrollment"
)

// ctxKey is an unexported context key type so callers must go through
// HostIDFromContext.
type ctxKey int

const ctxKeyHostID ctxKey = iota + 1

// HostIDFromContext returns the host_id pinned by the HostToken middleware.
// The second return is false when the context was not wrapped (caller
// bypassed middleware).
func HostIDFromContext(ctx context.Context) (string, bool) {
	v := ctx.Value(ctxKeyHostID)
	s, ok := v.(string)
	return s, ok && s != ""
}

// WithHostIDForTest returns a context with the host_id pinned. Exported for
// downstream test packages that exercise handlers directly. Production code
// must not call this.
func WithHostIDForTest(ctx context.Context, hostID string) context.Context {
	return context.WithValue(ctx, ctxKeyHostID, hostID)
}

// HostToken returns a middleware that validates an agent's bearer token
// against the enrollment store. On success the middleware pins host_id on
// the request context and the active span. On failure it returns 401 with
// a typed reason.
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
				// Token length is always 43 for an issued token, so unknown +
				// revoked both surface as ErrTokenMismatch. We don't distinguish
				// because doing so is an oracle for token-still-active probing.
				fail(ctx, w, logger, "invalid_token")
				return
			case err != nil:
				// DB / internal errors must not look like a revocation to the
				// agent -- 401 here would trip the re-enroll hook in the agent
				// and burn its throttle during outages. 503 + no WWW-Authenticate.
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

// extractBearer returns the token portion of an Authorization: Bearer <token>
// header. Returns ("", false) for missing / malformed / empty-token headers.
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

// failStatus is the general failure writer. WWW-Authenticate is set only on
// 401 responses; sending it with a 5xx would encourage retry-with-new-
// credentials logic that cannot help when the real problem is server-side.
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
