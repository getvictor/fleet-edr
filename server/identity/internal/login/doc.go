// Package login serves the operator authentication HTTP surface:
//
//	POST   /api/session  - public, rate-limited; verifies credentials,
//	                       creates a session row, sets the session cookie,
//	                       returns the user + CSRF token in the response body.
//	GET    /api/session  - session-required; returns the current user + CSRF token.
//	DELETE /api/session  - public, idempotent; best-effort row delete + cookie clear.
//
// The handler delegates business logic to identity/internal/service. It owns
// the HTTP-flavoured concerns (rate limiting, request body parsing, cookie
// construction, response formatting, audit log).
//
// Renamed from server/session/ to disambiguate from server/identity/internal/sessions/.
//
// Internal to the identity bounded context. Do not import from outside
// server/identity/.
package login
