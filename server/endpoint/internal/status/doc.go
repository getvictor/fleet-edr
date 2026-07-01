// Package status serves the agent-facing health check-in: POST /api/status.
//
// It is mounted behind the host-token middleware, so by the time the handler runs the request is authenticated and the host_id is
// pinned on the context (the check-in never trusts a host id from the body). The handler decodes an idempotent StatusReport snapshot
// and hands it to api.Service.RecordStatus, which validates the component status enum, computes the server-side overall rollup, and
// upserts the latest per-host row. The check-in is current-state, not an event: every post fully replaces the host's prior snapshot
// (issue #359), so a dropped post self-heals on the next one.
package status
