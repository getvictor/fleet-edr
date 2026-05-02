// Package middleware holds the HostToken HTTP middleware that gates
// every agent-facing endpoint. It extracts the Bearer token from the
// Authorization header, calls api.Service.VerifyToken to resolve it to
// a host_id, and pins the host_id on the request context (read by
// downstream handlers via api.HostIDFromContext).
//
// Internal to the endpoint bounded context. Do not import from outside
// server/endpoint/. The ctx-key helpers (HostIDFromContext,
// WithHostIDForTest) live here but are forwarded from
// server/endpoint/api/middleware_contracts.go so other contexts can
// read the host_id from ctx without importing this package.
package middleware
