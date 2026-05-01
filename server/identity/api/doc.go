// Package api is the public surface of the identity bounded context.
//
// Other contexts may import this package. It contains value types
// (User, Session, LoginResult), the Service interface that
// orchestrates operator authentication, error sentinels, encoder
// helpers (EncodeToken, DecodeToken), and context helpers
// (UserIDFromContext, SessionFromContext) used by middleware.
//
// The package contains no executable logic, no database code, and no
// HTTP handlers. Implementations live under server/identity/internal/.
//
// See docs/adr/0004-modular-monolith-bounded-contexts.md for the
// dependency rules that govern this package.
package api
