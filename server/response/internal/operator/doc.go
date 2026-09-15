// Package operator serves the session-gated operator routes:
//
//	POST /api/commands                       - admin issues a command for a target host
//	GET  /api/commands/{id}                  - admin reads a single command by id
//	POST /api/commands/{id}/cancel           - admin withdraws a command no agent has taken
//	GET  /api/containment                    - lists every host with a containment state (host.read)
//	GET  /api/hosts/{host_id}/containment    - reads a host's containment state (host.read)
//	POST /api/hosts/{host_id}/containment    - contains or releases a host (host.isolate, reason required)
//
// Every route is wrapped in identity.Session + identity.CSRF
// middleware by cmd/main (CSRF applies to the unsafe methods). POST /api/commands records the action via
// trace span attributes + a slog audit line (admin_action,
// host_id, edr.command.type, edr.command.id); the commands table
// itself does NOT carry per-row audit columns: audit lives in the
// observability pipeline. Adding persisted audit (admin_actor +
// reason) is a future schema extension tracked alongside operator
// authn hardening.
package operator
