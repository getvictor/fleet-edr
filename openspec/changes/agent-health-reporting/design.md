# Design notes

## Health is a snapshot channel, not an event stream

Two shapes were considered for the transport. A new event type on the append-only `POST /api/events` pipeline (partitioned out at ingest like `snapshot_heartbeat` already is) would reuse the auth, gzip, and batch plumbing. A dedicated check-in endpoint carries an idempotent current-state snapshot instead.

Decision: a dedicated `POST /api/status`. Health is current-state, not an append-only log: the server only ever wants the latest snapshot per host, last-writer-wins, and a missed post must self-heal on the next one. Riding an append-only stream would either accumulate stale rows to reconcile or abuse the stream as an upsert. The dedicated endpoint keeps snapshot semantics honest, keeps status off the detection ingest hot path, and matches Elastic Fleet's check-in model. The accepted cost is one more route and a small poster loop in the agent.

## The conditions model, not one field per signal

The payload is a list of component-health conditions, each `{type, status, reason, message, last_transition_ns}`, rather than a fixed struct with a field per known signal. This is the Kubernetes conditions pattern. The `status` field is a small closed enum validated at the ingest boundary; `type` and `reason` are open string vocabularies owned by the agent. A new signal (DNS proxy, queue depth, policy staleness) is then one more entry the agent emits, stored generically by the server and rendered from its own message, with no wire change, no migration, and no UI-framework change. This is the whole reason to build the channel now rather than a boolean: the marginal cost over the boolean is small and it is paid once.

## Rollup is computed on the server

The overall host-health state is derived on the server as the worst of the components: any `unhealthy` yields `unhealthy`; else any `degraded` yields `degraded`; a host with no components yields `unknown`; otherwise `healthy`. It is not sent by the agent. Keeping the rollup policy server-side means tightening what counts as unhealthy (for example promoting a `degraded` DNS-proxy state to `unhealthy`) is a server-only change that takes effect for every already-deployed agent.

## Context ownership: endpoint

Host lifecycle (enrollment, host-token verification) lives in the endpoint context, and the host-token middleware that a check-in must pass through is already there (`server/endpoint/internal/middleware/hosttoken.go`). So the `host_health` table, the `POST /api/status` handler, the service, and the upsert store all live in the endpoint context. The detection host list already LEFT JOINs the endpoint `enrollments` table via the shared `host_id` in the same MySQL database to decorate each row with hostname and OS version (`server/detection/internal/mysql/hosts.go`); health decorates the same row through a second `LEFT JOIN host_health` on the same key. This is the established cross-context read path for the host list and adds no new coupling.

## Persistence: JSON snapshot plus an indexed rollup column

`host_health` stores the full component list as a JSON column (open-ended growth: a new component type needs no schema change) and the computed `overall_status` as a short enum column with an index. The indexed enum makes the common operator query, "show me hosts needing attention," a cheap indexed filter without unpacking JSON, while the JSON keeps the detail payload complete and future-proof. The row is keyed on `host_id` with a last-writer-wins upsert, so out-of-order or retried posts converge on the latest `reported_at_ns`.

## Never-connected vs connection-lost

The agent already tracks per-service XPC connectivity (`Receiver.connected`) and fires `OnConnected`/`OnDisconnected` on transitions (`agent/receiver/loop.go`). The registry adds one bit per component: whether it has ever seen a successful session. Before the first connect the component is `unhealthy`/`never_connected`, which is exactly the fresh-install activation gap in #359. After a connect and then a drop while the agent keeps running it is `unhealthy`/`connection_lost`, which is the tamper-adjacent signal a later alert rule will consume. The registry stamps `last_transition_ns` only when the status actually changes, so "since when" is meaningful and the poster can debounce a burst of connect retries into one report.

## Cadence

The poster reports on startup (so a host that comes up with a dead sensor is visible immediately), on any component transition (debounced roughly two seconds to coalesce connect-retry churn), and on a periodic floor (roughly every 60 seconds) so the server view refreshes even with no transitions. A dedicated poster rather than piggybacking the five-second command poll keeps status independent of the response context and avoids inflating command-poll traffic with a body. The check-in may also bump `last_seen_ns` as a liveness side effect, but the existing command-poll heartbeat is left in place so liveness does not regress if the poster is disabled or a client is old.

## Wire types are defined per side, not shared

The agent and server do not share a Go module or wire types today (the agent posts enrollment as an ad-hoc payload; the server defines `EnrollRequest`). This change keeps that convention: the server defines `StatusReport`/`ComponentHealth` in `server/endpoint/api`, and the agent builds the same JSON from its own struct. The contract is pinned by a PBT round-trip on the server struct plus an example-based wire pin of the first-two-components shape, so the two sides cannot drift silently.

## Must-have vs deferred

Shipped here: the extensible check-in channel; the agent registry with never-connected vs connection-lost; server persistence, boundary enum validation, and the rollup; and the Hosts badge plus host-detail conditions panel (the operator-visible payoff #359 asks for).

Deferred to follow-ups (features, not holes): the tamper-detection alert rule for a `connection_lost` transition; further components (DNS proxy, event-queue depth and drops, applied policy version and staleness, agent CPU/memory, disk pressure, clock skew, cloud connectivity); and replacing the inferred-liveness side-channels with the check-in as the single source of last-seen.
