// Package operator serves the session-gated operator routes:
//
//	POST /api/commands            - admin issues a command for a target host
//	GET  /api/commands/{id}       - admin reads a single command by id
//
// Both routes are wrapped in identity.Session + identity.CSRF
// middleware by cmd/main. POST /api/commands records the action via
// trace span attributes + a slog audit line (admin_action,
// host_id, edr.command.type, edr.command.id); the commands table
// itself does NOT carry per-row audit columns: audit lives in the
// observability pipeline. Adding persisted audit (admin_actor +
// reason) is a future schema extension tracked alongside operator
// authn hardening.
package operator
