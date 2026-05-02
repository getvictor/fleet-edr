// Package agent serves the host-token-gated agent routes:
//
//	GET /api/commands             - agent polls its pending queue (heartbeat side effect)
//	PUT /api/commands/{id}        - agent acks / completes / fails a command
//
// Both routes are wrapped in endpoint.HostToken middleware by
// cmd/main; the handlers read the pinned host_id via
// endpointapi.HostIDFromContext and treat any ?host_id= query param
// as informational only (a valid token for host A cannot read host
// B's commands).
package agent
