// Package operator serves the session-gated operator routes:
//
//	POST /api/commands                       - admin issues a command for a target host
//	GET  /api/commands/{id}                  - admin reads a single command by id
//	POST /api/commands/{id}/cancel           - admin withdraws a command no agent has taken
//	GET  /api/containment                    - lists every host with a containment state (host.read)
//	GET  /api/hosts/{host_id}/containment    - reads a host's containment state (host.read)
//	POST /api/hosts/{host_id}/containment    - contains or releases a host (host.isolate, reason required)
//
// Every route is wrapped in identity.Session + identity.CSRF middleware by cmd/main (CSRF applies to the unsafe methods).
//
// Every state-changing route here records a persisted audit row, and records it durably: the entry is committed to this context's
// audit outbox in the same transaction as the change it describes, and delivered to the identity audit log afterwards (issue #1070).
// So an issued command, a withdrawn one, and a containment change cannot exist without a row naming who made them. The commands table
// carries no audit columns of its own; the row lives in the audit log, and the span attributes and slog line (admin_action, host_id,
// edr.command.type, edr.command.id) remain as the observability view of the same action.
package operator
