## Why

Today every host learns about operator actions (kill a process, push a refreshed blocklist, rotate its token) by short-polling `GET /api/commands` on a fixed interval (5s). Two costs follow from that: command-delivery latency has a floor of one poll interval even when the server already has the command queued, and idle hosts generate steady request volume that scales with host count rather than with how much work there actually is. Interactive response (RTR, live containment) is impossible on a poll at all, because request/response cannot carry an interactive exchange.

This is Phase 3 of the scale-to-100k control-channel plan (`ai/scale-100k/plan.md` section 3.6). The prerequisites it named are now in tree: self-validating signed host tokens (#454) give once-per-connection auth with no per-request database lookup, the agent already pins the server leaf certificate, and the agent already holds an HTTP/2 connection with keep-alive PINGs. What is missing is the persistent push channel itself.

This change builds the minimal real-time control channel that fits the current pilot envelope (10 to 500 endpoints, single-VM and quickstart) without adopting a new messaging system. It deliberately does NOT stand up the NATS routing backplane or interactive RTR yet: per ADR-0016 (accepted 2026-06-28) a new messaging substrate stays deferred until the fleet outgrows the pilot, and there is no RTR consumer today. The channel is built so RTR layers onto it later without a second transport.

## What Changes

- **The agent holds one persistent bidirectional control connection to the server**, authenticated once at connect with the host's signed bearer token (#454) carried in connection metadata, over the same server-TLS plus leaf-certificate pinning the agent already applies. There is no client-certificate PKI; mTLS stays a later opt-in hardening upgrade on this same channel, not a prerequisite.
- **Queued commands are pushed over the connection in real time** instead of waiting for a poll. A new in-server control gateway holds the live agent connections and learns about queued work by watching the existing MySQL `commands` table. Delivery latency drops to immediate for a command queued on the replica that holds the host's connection (an in-process fast path) and to a bounded watch interval (1s) for a command queued on a different replica. No new messaging system is introduced: routing rides the existing shared MySQL substrate, consistent with ADR-0016.
- **Command acknowledgement and outcome reporting move onto the same connection**, advancing each command through the same acknowledged-then-completed-or-failed lifecycle and the same server-side state-transition rules as the polled path. The `commands` table, its status enum, and the transition matrix are unchanged: the gateway is a second transport in front of the unchanged command service, not a new data model.
- **The connection is authoritative host liveness.** While a host holds an open connection the server treats it as online and advances its last-seen time without needing a telemetry upload or a command poll; a disconnect reflects in the host's online status. This replaces the poll side effect that advances last-seen today.
- **The short-poll path is retained as the degraded floor.** The agent prefers the connection when it is up and falls back to polling `GET /api/commands` only when the connection cannot be established or has dropped, so a host is never left without a command path. The polled cadence and lifecycle are unchanged on the fallback path. No HTTP long-poll is built: a dedicated long-poll fallback stays evidence-gated per the issue.
- **Delivery is at-least-once and idempotent by command identity.** The watch-plus-fast-path design can offer the same command to a connection more than once; the agent treats a re-delivered command whose lifecycle has already advanced as a no-op, so a command is never executed twice.
- **A revoked or expired host token terminates the connection** within the existing revocation-propagation bound, so a deauthorized host cannot retain a live control channel.
- **ADR-0010 is amended** to name the control gateway as a sanctioned stateful tier: it holds live connections (sockets keyed by host) as its only in-process state, persists nothing durable, and a gateway loss forces affected agents to reconnect with no command loss because command state stays in MySQL.

## Capabilities

### New Capabilities

- `agent-control-channel`: the persistent authenticated push connection between agent and server. Owns connect-time authentication, real-time command delivery, outcome reporting over the connection, host-scoped isolation on the connection, connection-presence liveness, silent-failure detection with reconnect, revocation-driven teardown, and idempotent at-least-once delivery.

### Modified Capabilities

- `agent-command-executor`: a new requirement that the persistent control connection is preferred for command delivery and outcome reporting, and that the existing poll is the degraded fallback floor used only when the connection is unavailable. The polled cadence, lifecycle, and host-scoping requirements are otherwise unchanged.
- `server-availability`: the "holds no in-process state that survives a request lifetime" invariant is modified to name the control gateway as the one sanctioned stateful tier (live connections only, nothing durable, losable on reconnect without command loss), so it is read as a bounded carve-out rather than a defect.
- `server-configuration`: the fixed-constants enumeration is extended to name the gateway command-watch interval, keeping it a compiled constant rather than an operator environment knob.

## Impact

- **Affected specs:** `agent-control-channel` (new, 8 added requirements), `agent-command-executor` (1 added requirement), `server-availability` (1 modified requirement), `server-configuration` (1 modified requirement).
- **Affected code:** new control-gateway transport and `commands`-table watcher in the `response` context (`server/response/`); the gateway reuses `response.api.Service` (`Insert`/`InsertBatch`/`ListForHost`/`UpdateStatus`) unchanged and the `endpoint` context's host-token verify plus revocation snapshot for connect auth; the `detection` host-seen closure for liveness. Agent side: a control-connection client alongside `agent/commander/` that prefers the connection and falls back to the existing poll loop; reuse of the pinned TLS config and the shared transport. Wiring in `server/cmd/fleet-edr-server/main.go` mounts the gateway listener; the gateway is embedded in the server binary (no new deployable) for the pilot and single-VM profiles.
- **No schema change:** the `commands` table, status enum, and transition matrix are unchanged; no migration is added.
- **Preserved invariants:** ADR-0010 (the gateway is the named, bounded stateful carve-out; command state stays in MySQL), ADR-0011 (multi-replica behind a load balancer; any replica embeds a gateway and a host pins to one replica for its connection lifetime), ADR-0016 (no new messaging substrate; routing rides the existing MySQL queue), the agent-command-executor lifecycle and host-scoping, and OTel trace propagation (trace context propagates over the connection as it does over the HTTP paths today).
- **Out of scope (later, evidence-gated):** the NATS routing backplane for cross-gateway fan-out at scale, interactive RTR / live shell (this connection is its substrate), mTLS / hardware-bound identity, and a separate `fleet-edr-gateway` binary for the distributed profile.
- **Verification:** a real-MySQL integration test asserts a queued command is pushed to a connected fake agent and acked over the connection with the same status transitions as the poll path; cross-host isolation on the connection; a revoked token closes the connection; duplicate delivery executes once; and the agent falls back to the poll and still delivers when the connection cannot establish.

## Rollback

This change touches the agent protocol, so rollback is staged and non-destructive:

- No persisted state or schema changes: there is nothing to migrate back. The `commands` table is untouched.
- The short-poll path is retained and remains correct on its own. Disabling the gateway (not mounting the listener, or the agent not opening the connection) returns the system to pure polling with no data loss; queued commands are still delivered on the next poll.
- A server replica running the gateway and a replica not running it can coexist behind the load balancer during a rolling upgrade: an agent that cannot open a connection to its replica falls back to polling, which every replica still serves.
