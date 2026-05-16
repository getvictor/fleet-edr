package middleware

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/httpserver"
)

// HostToken returns a middleware that validates an agent's bearer token against the endpoint Service. On success the middleware
// pins host_id on the request context (via api.WithHostID) and the active OTel span. On failure it returns 401 with a typed reason;
// on infra outage it returns 503 (so an agent doesn't misinterpret a transient DB blip as token revocation and burn its re-enroll
// throttle).
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
				httpserver.WriteAuthFailure(ctx, w, logger, http.StatusUnauthorized, "missing_bearer")
				return
			}
			hostID, err := svc.VerifyToken(ctx, token)
			switch {
			case errors.Is(err, api.ErrInvalidToken):
				// Unknown + revoked both surface as ErrInvalidToken. We don't distinguish; doing so would be an oracle
				// for token-still-active probing.
				httpserver.WriteAuthFailure(ctx, w, logger, http.StatusUnauthorized, "invalid_token")
				return
			case err != nil:
				logger.ErrorContext(ctx, "authn verify", "err", err)
				httpserver.WriteAuthFailure(ctx, w, logger, http.StatusServiceUnavailable, "verifier_unavailable")
				return
			}
			trace.SpanFromContext(ctx).SetAttributes(attribute.String(attrkeys.HostID, hostID))
			next.ServeHTTP(w, r.WithContext(api.WithHostID(ctx, hostID)))
		})
	}
}

// extractBearer returns the token portion of an Authorization: Bearer <token> header. The scheme name is matched case-insensitively
// per RFC 7235 §2.1; clients/intermediaries that normalise the casing to "bearer" are accepted. Returns ("", false) for missing /
// malformed / empty-token headers.
func extractBearer(r *http.Request) (string, bool) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	scheme, rest, ok := strings.Cut(auth, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token := strings.TrimSpace(rest)
	if token == "" {
		return "", false
	}
	return token, true
}
