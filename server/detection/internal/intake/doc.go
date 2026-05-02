// Package intake serves the agent-facing ingest route plus the
// unauthenticated health probes:
//
//	POST /api/events     - agent posts a JSON array of events
//	GET  /livez          - liveness probe (200 if process is up)
//	GET  /readyz         - readiness probe (200 if DB ping succeeds)
//	GET  /health         - alias for /readyz
//
// POST /api/events is wrapped in endpoint.HostToken middleware by
// cmd/main; the handler reads the pinned host_id from request
// context and rejects any payload whose host_id doesn't match
// (phase-2 regression coverage).
package intake
