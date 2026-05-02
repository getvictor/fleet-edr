// Package operator serves the session-gated operator endpoints for
// enrollment management:
//
//	GET  /api/enrollments                          - list enrollments
//	POST /api/enrollments/{host_id}/revoke          - revoke an enrollment
//
// Both call into endpoint/api.Service. The session + CSRF middlewares
// are applied at cmd/main wiring time, mirroring the operator-side
// pattern from identity.
//
// Internal to the endpoint bounded context. Do not import from outside
// server/endpoint/.
package operator
