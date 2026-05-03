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

// WriteAuthFailure writes a typed JSON auth/CSRF failure response for
// endpoints protected by a Bearer token (e.g. agent enrollment / event
// upload). Cookie-session endpoints must use WriteCookieAuthFailure
// instead so they don't emit a misleading Bearer challenge: see the doc
// comment there.
//
// Behaviour:
//   - Sets a `WWW-Authenticate: Bearer error="invalid_token"` challenge on
//     401 only. Sending it on 5xx would push agents toward
//     retry-with-new-credentials when the real problem is server-side.
//   - Tags the active OTel span with auth.result=fail + auth.reason so the
//     same span attributes show up regardless of which middleware
//     produced the failure.
//   - Emits a single warn log line with the reason + status.
func WriteAuthFailure(ctx context.Context, w http.ResponseWriter, logger *slog.Logger, status int, reason string) {
	tagAuthFailure(ctx, logger, status, reason)
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	}
	NoStoreJSON(ctx, logger, w, status, AuthErrBody{Error: reason})
}

// WriteCookieAuthFailure is the cookie-session counterpart to
// WriteAuthFailure. It writes a byte-identical JSON body and emits the
// same span attributes + warn log line, but never sets a WWW-Authenticate
// header.
//
// Cookie-session endpoints (browser UI, /api/session, anything behind the
// Session middleware) reject by design any non-cookie credential, so a
// Bearer challenge is wrong on the wire: browsers' HTTP-Basic dialogs
// ignore it, `curl --anyauth` fires a redundant retry round, and tools
// that surface WWW-Authenticate to the user just print a confusing
// "expected Bearer" hint when the real recovery is "open the login page."
// RFC 7235 registers no scheme for cookie auth and discourages inventing
// one, so we omit the header entirely. The JSON `{"error": "..."}` body
// remains the actionable failure signal for both UI redirects and
// scripted clients.
func WriteCookieAuthFailure(ctx context.Context, w http.ResponseWriter, logger *slog.Logger, status int, reason string) {
	tagAuthFailure(ctx, logger, status, reason)
	NoStoreJSON(ctx, logger, w, status, AuthErrBody{Error: reason})
}

// tagAuthFailure is the shared bookkeeping for both WriteAuthFailure and
// WriteCookieAuthFailure: pin auth.result/auth.reason on the active OTel
// span and emit a single warn log line. Pulled out so the two writers
// stay byte-identical in everything except the WWW-Authenticate header.
func tagAuthFailure(ctx context.Context, logger *slog.Logger, status int, reason string) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.String(attrkeys.AuthResult, "fail"),
		attribute.String(attrkeys.AuthReason, reason),
	)
	if logger != nil {
		logger.WarnContext(ctx, "authn failed", attrkeys.AuthReason, reason, "status", status)
	}
}
