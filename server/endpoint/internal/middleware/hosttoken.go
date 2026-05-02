package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/endpoint/api"
)

// HostToken returns a middleware that validates an agent's bearer token
// against the endpoint Service. On success the middleware pins host_id
// on the request context (via api.WithHostID) and the active OTel span.
// On failure it returns 401 with a typed reason; on infra outage it
// returns 503 (so an agent doesn't misinterpret a transient DB blip as
// token revocation and burn its re-enroll throttle).
func HostToken(svc api.Service, logger *slog.Logger) func(http.Handler) http.Handler {
	if svc == nil {
		panic("endpoint middleware: Service must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			token, ok := extractBearer(r)
			if !ok {
				fail(ctx, w, logger, http.StatusUnauthorized, "missing_bearer")
				return
			}
			hostID, err := svc.VerifyToken(ctx, token)
			switch {
			case errors.Is(err, api.ErrInvalidToken):
				// Unknown + revoked both surface as ErrInvalidToken. We
				// don't distinguish; doing so would be an oracle for
				// token-still-active probing.
				fail(ctx, w, logger, http.StatusUnauthorized, "invalid_token")
				return
			case err != nil:
				logger.ErrorContext(ctx, "authn verify", "err", err)
				fail(ctx, w, logger, http.StatusServiceUnavailable, "verifier_unavailable")
				return
			}
			trace.SpanFromContext(ctx).SetAttributes(attribute.String(attrkeys.HostID, hostID))
			next.ServeHTTP(w, r.WithContext(api.WithHostID(ctx, hostID)))
		})
	}
}

// extractBearer returns the token portion of an Authorization: Bearer
// <token> header. Returns ("", false) for missing / malformed /
// empty-token headers.
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

// errBody is the JSON shape this middleware writes on failure.
type errBody struct {
	Error string `json:"error"`
}

// fail writes a structured JSON error + audit log + span attributes.
// WWW-Authenticate is set only on 401 responses; sending it with a 5xx
// would encourage retry-with-new-credentials logic that cannot help
// when the real problem is server-side.
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
