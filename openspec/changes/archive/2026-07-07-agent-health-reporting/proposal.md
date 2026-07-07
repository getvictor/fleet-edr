## Why

When the system extensions are not activated (fresh install at loginwindow, user declined approval, user disabled the login item), the only signal is a `receiver connect` WARN loop in `/var/log/fleet-edr-agent.log` on the endpoint. The server's Hosts page shows the host as enrolled and recently seen, indistinguishable from a fully healthy host. The 2026-06-12 QA session demonstrated how invisible this is: a fresh edr-qa install enrolled cleanly and sat eventless for 20+ minutes before anyone looked at the log (issue #359).

The agent has no check-in payload today. Liveness is only inferred, from the `GET /api/commands` poll (which bumps `hosts.last_seen_ns` via the response heartbeat closure) and from `snapshot_heartbeat` events that the ingest path drops. Neither carries agent self-state, so the server cannot tell a healthy host from one whose sensor never came up. A single `extension_connected` boolean would close #359 but would have to be re-plumbed end to end the first time we report any other status, and a top-tier EDR reports many: sensor connectivity, DNS proxy state, event-queue pressure, applied policy version, resource pressure, clock skew.

This change ships a general, extensible agent-health channel and makes system-extension activation its first two signals. The shape follows the industry norm that Elastic Agent and CrowdStrike Falcon converge on: a periodic, idempotent check-in carrying a list of component-health conditions, rolled up to one host state on the server. Adding a future signal is then an agent-only change with no wire break, no server migration, and no UI rewrite.

## What changes

- Add a dedicated host check-in `POST /api/status` (host-token authed, endpoint context) carrying an idempotent status snapshot: the agent version and a list of component-health conditions, each with a stable `type`, a closed `status` enum (`healthy`/`degraded`/`unhealthy`/`unknown`), an open machine-readable `reason`, a human `message`, and the timestamp the component last changed state. The snapshot is last-writer-wins; a missed post self-heals on the next one.
- The agent maintains a per-component health registry updated from its existing per-service XPC connectivity state and `OnConnected`/`OnDisconnected` transition hooks. It reports the endpoint-security extension and the network extension as the first two components, distinguishing `never_connected` (the fresh-install activation gap) from `connection_lost` (a component that connected and then dropped while the agent kept running). It posts on startup, on any component transition (debounced), and on a periodic floor.
- The server persists the latest snapshot per host, validates the `status` enum at the boundary while accepting unknown `type`/`reason` strings, and computes the overall host-health rollup server-side (worst-of the components). The rollup policy lives only on the server so tightening what counts as unhealthy needs no agent redeploy.
- The host API surfaces health: the Hosts list carries the per-host `overall_status`; the single-host detail carries the full component list. Read access reuses `ActionHostRead`; no new permission.
- The web UI adds a health badge column to the Hosts list and a conditions panel to the host detail, so a fleet-wide activation gap is visible at a glance (for example "needs attention: security extension not activated").

Out of scope, tracked as follow-ups: a tamper-detection alert rule for a component going `connection_lost` while the agent keeps checking in (the `connection_lost` reason and `last_transition_ns` are the hooks it will consume); additional components (DNS proxy, event-queue depth, applied policy version and staleness, agent resource pressure, clock skew, cloud connectivity), each one more entry in the agent registry; and folding the check-in in as the single liveness source in place of the inferred side-channels.

## Capabilities

### Added capabilities

- `agent-status-reporting`: the agent maintains a per-component health registry from its XPC connectivity state, distinguishes never-connected from connection-lost per extension, and posts an idempotent status snapshot on startup, on transition, and periodically.
- `server-host-status`: the server accepts and persists the latest per-host status snapshot over a host-token-authed check-in, validates the status enum at the boundary while tolerating unknown component types, computes the overall health rollup, and exposes per-host health on the host API.

### Modified capabilities

- `web-ui`: add a per-host health badge to the Hosts list and a component-conditions panel to the host detail.

## Impact

- Code (agent): a new `agent/health/` registry, a new `agent/status/` poster loop (following the `RunRefresh` shape in `agent/enrollment/enrollment.go`), and registry wiring in the receiver loops (`agent/receiver/loop.go`) plus the agent main (`agent/cmd/fleet-edr-agent/main.go`).
- Code (server): a new endpoint migration `server/endpoint/migrations/00005_host_health.sql` creating a `host_health` table; the wire structs and validation in `server/endpoint/api`; a `POST /api/status` handler, service, and upsert store in the endpoint context (host-token middleware at `server/endpoint/internal/middleware/hosttoken.go`); a `LEFT JOIN host_health` decoration and an `OverallStatus` field on `HostSummary` in the detection host list (`server/detection/internal/mysql/hosts.go`, `server/detection/api/types.go`); and the full component list on the single-host detail response.
- Code (UI): `ui/src/types.ts` (extend `HostSummary`, add `ComponentHealth`), `ui/src/components/HostList.tsx` (badge column), the host detail panel (`ui/src/components/ProcessTree.tsx` header or a small new component), reusing `ui/src/components/ui/Badge.tsx`, each with a `*.test.tsx` sibling.
- Data: one additive migration creating `host_health`. No backfill. A host with no snapshot rolls up to `unknown`. Rollback drops the table; the host list falls back to its current shape.
- APIs: one new host-token-authed route `POST /api/status`. The host list response gains `overall_status`; the host detail response gains the component list. No change to the event schema or the persisted host token.
- Security: the check-in is authenticated with the existing host token; the payload carries no secret. Unknown `type`/`reason` strings are stored but the `status` enum is validated at the boundary.
- Rollback is a code revert plus dropping `host_health`; a deployment with no snapshots behaves as before with every host reading `unknown`.
