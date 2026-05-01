// Package middleware holds the operator-session HTTP middleware:
//
//   - Session reads the edr_session cookie, looks up the session row via the
//     identity service, and pins user_id + session on the request context.
//   - CSRF runs after Session and validates the X-Csrf-Token header on unsafe
//     methods via constant-time compare.
//
// Wire as Session(CSRF(handler)) so Session pins the session before CSRF
// reads it. The two ctx-key helpers (UserIDFromContext, SessionFromContext)
// are forwarded from identity/api so other contexts can read the values
// without importing this package.
//
// Internal to the identity bounded context. Do not import from outside
// server/identity/.
package middleware
