package httpserver

import (
	"context"
	"log/slog"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/attrkeys"
)

// AuthErrBody is the JSON shape every auth/CSRF middleware in the project
// writes on failure. Exported so callers can reuse the same wire format
// when they don't go through WriteAuthFailure (e.g. handlers that fail
// before any middleware fires).
type AuthErrBody struct {
	Error string `json:"error"`
}

// WriteAuthFailure writes a typed JSON auth/CSRF failure response with
// the project's standard wire shape. Centralised so the host-token
// middleware (endpoint context) and the session middleware (identity
// context) write byte-identical 401 / 403 / 503 bodies.
//
// Behaviour:
//   - Sets a `WWW-Authenticate: Bearer error="invalid_token"` challenge on
//     401 only — sending it on 5xx would push agents toward
//     retry-with-new-credentials when the real problem is server-side.
//   - Tags the active OTel span with auth.result=fail + auth.reason so the
//     same span attributes show up regardless of which middleware
//     produced the failure.
//   - Emits a single warn log line with the reason + status.
func WriteAuthFailure(ctx context.Context, w http.ResponseWriter, logger *slog.Logger, status int, reason string) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.String(attrkeys.AuthResult, "fail"),
		attribute.String(attrkeys.AuthReason, reason),
	)
	if logger != nil {
		logger.WarnContext(ctx, "authn failed", attrkeys.AuthReason, reason, "status", status)
	}
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	}
	NoStoreJSON(ctx, logger, w, status, AuthErrBody{Error: reason})
}
