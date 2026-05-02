// Package api is the public surface of the endpoint bounded context.
//
// Other contexts may import this package. It contains value types
// (Enrollment, EnrollRequest, EnrollResponse), the Service interface
// that orchestrates host enrollment + token verification, error
// sentinels, context helpers (HostIDFromContext, WithHostIDForTest)
// used by the host-token middleware, and the narrow PolicyProvider
// interface the enroll handler needs at boot time. The
// CommandInserter shape is a closure type defined in
// endpoint/bootstrap (it was an interface here in phases 2 and 3;
// phase 4 simplified it to a func type satisfied by
// response.Service.Insert as a method value).
//
// The package contains no executable logic, no database code, and no
// HTTP handlers. Implementations live under server/endpoint/internal/.
//
// See docs/adr/0004-modular-monolith-bounded-contexts.md for the
// dependency rules that govern this package.
package api
