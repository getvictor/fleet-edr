package middleware

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/identity/api"
)

// BearerAuthenticator resolves a service-account access token into an actor. Implemented by serviceaccounts.Authenticator.
type BearerAuthenticator interface {
	Authenticate(token string, now time.Time) (*api.Actor, bool)
}

// APIAuth is the authentication front door for the operator API mux. It supports two transports, one authorization model (ADR-0013):
//
//   - A request carrying `Authorization: Bearer <token>` is a service account. The token is verified statelessly (no DB) and resolved
//     to an actor pinned on the context; CSRF does not apply (a bearer token is not an ambient credential). An invalid bearer token is
//     401, never a fall-through to the cookie path (so a bad token gets a clear answer, not a confusing "missing session cookie").
//   - Any other request takes the existing browser path: the session-cookie middleware then the CSRF middleware.
//
// Both paths leave an *api.Actor on the context for the downstream authz chokepoint, so handlers are transport-agnostic.
func APIAuth(
	auth BearerAuthenticator,
	sessionMW func(http.Handler) http.Handler,
	csrfMW func(http.Handler) http.Handler,
	logger *slog.Logger,
) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		sessionChain := sessionMW(csrfMW(next))
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, hasScheme := bearerToken(r)
			if !hasScheme {
				// No Bearer scheme at all: this is the browser. Hand off to cookie session + CSRF.
				sessionChain.ServeHTTP(w, r)
				return
			}
			// A Bearer scheme is present: this is a service-account request. It MUST authenticate as one; we never fall through to the
			// cookie path, so a malformed/empty/invalid bearer is a clear 401 rather than a confusing "missing session cookie".
			actor, ok := auth.Authenticate(token, time.Now())
			if !ok {
				// Invalid / empty / expired / wrong-audience / revoked all collapse to one opaque 401 (no oracle).
				httpserver.WriteAuthFailure(r.Context(), w, logger, http.StatusUnauthorized, "invalid_token")
				return
			}
			next.ServeHTTP(w, r.WithContext(api.WithActor(r.Context(), actor)))
		})
	}
}

// bearerToken reports whether the request uses the `Authorization: Bearer` scheme (matched case-insensitively per RFC 7235) and
// returns the token portion (possibly empty). hasScheme distinguishes "no bearer credential" (delegate to cookies) from "bearer
// scheme present but token empty/malformed" (authenticate, and 401 on failure).
func bearerToken(r *http.Request) (token string, hasScheme bool) {
	const scheme = "Bearer"
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(auth) < len(scheme) || !strings.EqualFold(auth[:len(scheme)], scheme) {
		return "", false
	}
	rest := auth[len(scheme):]
	// The scheme name must be followed by whitespace or end-of-string; otherwise "Bearerfoo" would falsely match the scheme. An empty
	// rest ("Authorization: Bearer") is a present-but-empty credential, which the caller treats as an invalid bearer (401), not a
	// missing one (cookie fall-through).
	if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
		return "", false
	}
	return strings.TrimSpace(rest), true
}
