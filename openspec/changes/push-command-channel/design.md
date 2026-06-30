# Design: push-based command channel

This captures the implementation decisions behind the `push-command-channel` change. The spec deltas state observable behavior; this document records the transport, routing, and tier choices that realize it, and the boundaries that keep it inside the current architecture.

## Transport: persistent gRPC bidirectional stream

The control connection is a single gRPC bidirectional stream over the agent's existing pinned-TLS, HTTP/2 connection. One RPC carries command frames down (server to agent) and outcome frames up (agent to server) on the same stream.

Why gRPC bidi rather than SSE or a second poll:

- Outcome reporting needs an upstream channel, and the channel must be RTR-ready (interactive live shell is a streamed exchange in both directions). A server-to-agent-only transport (SSE) would not carry acks or RTR; a request/response transport cannot carry RTR at all. A bidi stream is the one shape that serves command push, acks, and future RTR without a second transport.
- gRPC gives a typed frame contract and rides the HTTP/2 connection the agent already holds (multiplexed, HPACK-compressed, keep-alive PINGs already tuned for half-open detection).
- The wire frames are a new serialized shape, so they ship a property-based round-trip test (`Marshal then Unmarshal == identity`) per repo convention.

gRPC and protobuf are promoted from indirect dependencies (today pulled in only by the OTel exporters) to direct ones. `otelgrpc` stats handlers propagate W3C trace context over stream metadata, the gRPC-side equivalent of the `otelhttp` wrapping on the REST paths, so the propagation invariant holds across the new transport.

## Auth: once per connection, reusing the signed host token

Auth happens once at stream open, not per frame. The agent presents its signed host token (#454) in the stream's opening metadata as `authorization: Bearer <token>`. A gRPC stream interceptor mirrors the existing host-token HTTP middleware: it verifies the token locally (HMAC signature plus expiry plus revocation-epoch snapshot, no database round-trip), pins the resulting `host_id` into the stream context, and rejects the open otherwise. The same revocation snapshot the HTTP middleware reads gates the stream, so a 503 on a revocation-snapshot blip is surfaced the same way (the agent retries rather than treating it as a hard deauth).

Transport security is server-TLS plus the agent's existing leaf-certificate SHA-256 pin (`ServerFingerprint`), reused verbatim via `credentials.NewTLS(pinnedTLSConfig)`. No client-certificate PKI. mTLS (ideally an agent-generated Secure Enclave key) is the later opt-in hardening upgrade on this same channel.

### Token refresh on a long-lived connection

The connect-time token expires (default 60m TTL) before a long-lived stream would naturally close. The agent already refreshes its token proactively at roughly two-thirds of TTL. On refresh the agent reconnects the stream with the fresh token. This is the simplest correct option (the agent already has reconnect machinery) and avoids an in-band re-auth frame. The reconnect is a sub-second blip covered by the poll fallback floor.

### Revocation tears down the connection

A live connection whose token has been revoked (epoch bumped) or has expired is closed by the gateway within the revocation-propagation bound. The gateway re-checks each held connection's token claims against the refreshed revocation snapshot on the snapshot's existing refresh cadence and closes connections that no longer validate. A deauthorized host cannot keep a live control channel open past the bound.

## Routing without a new messaging system

The gateway is embedded in the server binary. Each replica behind the load balancer runs a gateway; an agent's connection lands on whichever replica the load balancer routed it to and stays pinned to that replica for the connection's lifetime (the connection is the affinity, no LB stickiness needed).

**At most one connection per host.** The registry is keyed by `host_id`, and a reconnect (after a token refresh, a network transition, or a races where the old connection has not yet been noticed as dead) can open a second connection for a host that already has one. The gateway SHALL close and clean up any existing connection for a `host_id` before registering a new one, and treat the new connection as the sole authoritative channel for that host. Without this, the stale connection leaks its goroutine and file descriptor and could receive a duplicate push. This applies on the replica holding the connection; two connections for one host landing on two different replicas is the cross-replica reconnect case, resolved as the old replica observes its connection drop.

Commands are queued by the operator UI (`POST /api/commands`), by application-control policy fan-out (`InsertBatch`), and by enroll fan-out. The replica that queues a command is not necessarily the one holding the target host's connection. Two delivery paths cover this without a bus:

1. **In-process fast path (same replica).** When a command is queued on the replica that already holds the target host's connection, the gateway is notified in-process and pushes immediately. At the single-replica pilot and single-VM default this covers every command, so delivery is effectively instant.
2. **MySQL watch (cross-replica floor).** Each gateway watches the `commands` table on a fixed 1s interval, scoped to the hosts it actually holds: `SELECT id, host_id, command_type, payload FROM commands WHERE status = 'pending' AND host_id IN (<locally-held host ids>)`. Constraining on `host_id` is what lets the query seek the existing `(host_id, status)` index rather than scanning every pending row in the fleet, and it transfers only the rows this replica can deliver. The `IN` list is the gateway's connected-host set (batched if a single gateway ever holds more connections than fit one statement). Each returned row is pushed to its connection, skipping IDs already in flight. A command queued on another replica is therefore delivered within at most the watch interval. A bare `WHERE status = 'pending'` (no `host_id` predicate) was rejected in review: it cannot use the leading-column index and would fan every replica's scan across the whole pending backlog, including commands queued for offline hosts.

This collapses O(hosts) agent polls into O(replicas) gateway watches and keeps all delivery state in MySQL, so ADR-0016's "no new messaging substrate at pilot scale" holds. The NATS backplane named in the scale plan is the later move when cross-gateway fan-out latency at scale demands it; it is explicitly out of scope here.

The 1s watch interval is a compiled constant, not an operator environment knob, consistent with the minimal-configuration-surface requirement and named in the `server-configuration` delta.

## Idempotent at-least-once delivery

The fast path and the watch can offer the same command to a connection more than once (for example, a fast-path push followed by a watch tick before the ack lands, or a re-delivery after a reconnect). Three things make this safe, and the third is a correctness fix surfaced in review:

- The gateway tracks the set of command IDs it has pushed to a connection and is awaiting an ack on (in-memory, per-connection, safe to lose), and skips re-pushing an ID already in flight on that connection.
- The agent dispatches by command ID: it runs a command's side effect at most once, keyed by ID, so a re-delivery never repeats the kill or the snapshot apply.
- The agent records each command's final outcome and, on re-delivery of a command it has already executed, **re-reports the recorded outcome rather than silently dropping it**. Silent-drop was wrong: if the agent executed a command and the completion report was lost before the server persisted it, the command stays `pending`, the watch re-delivers it, and a drop would leave it stuck `pending` forever. Re-reporting transitions it out of `pending`. This also avoids a `kill_process` re-execution returning "no such process" and overwriting a recorded success with a failure: the agent reports the cached outcome, it does not signal the (already-dead) PID again. On reconnect the agent likewise re-reports outcomes for commands it executed but whose reports may not have landed, so an acknowledged-but-unreported command is reconciled rather than orphaned. The server-side state machine backstops this: an outcome that is not a valid transition for the command's current status is rejected and treated by the agent as "already handled."

So a command is delivered at least once, its side effect runs at most once, and a lost outcome report is always reconciled rather than leaving the command stuck.

## Liveness

The poll side effect that advances `host.last_seen_ns` today moves onto the connection. The gateway bumps last-seen on connect and on the connection's keep-alive cadence via the same host-seen closure the poll path uses (`detection.RecordHostSeen`, injected so `response` keeps no hard dependency on `detection`). A disconnect is observable as the host going offline. The poll-driven heartbeat remains for the fallback path. This is strictly better than the poll heartbeat: online/offline truth is real-time, which the operator UI needs anyway.

## Fallback to the short-poll floor

The agent prefers the connection. While the connection is up the agent suppresses the command poll (it may keep a slow safety poll). When the connection cannot be established or drops, the agent reconnects with exponential backoff and jitter and resumes the existing 5s poll in the meantime, so commands keep flowing on the unchanged polled path. No HTTP long-poll is built; the short-poll is the only degraded floor, and a dedicated long-poll stays evidence-gated.

## ADR-0010 carve-out

The gateway is the first sanctioned stateful tier in the server. Its only in-process state is, per connection: the live socket (keyed by `host_id`), the connection's authentication metadata (the token's epoch and expiry, needed to re-check it against the revocation snapshot without a database lookup), and the set of in-flight command IDs. It persists nothing durable; all command state remains in MySQL. Losing a gateway or any connection forces the affected agents to reconnect (and to fall back to polling meanwhile), with no command loss because the command rows and their statuses are in the shared store. ADR-0010 is amended to name this carve-out so it is not read as a violation, and the `server-availability` stateless requirement is modified to match.

## Bounded-context placement

The gateway lives in the `response` context, which owns the `commands` table and the command service. It depends on the `endpoint` context's token-verify and revocation snapshot for connect auth and on the `detection` host-seen closure for liveness, both through the same injected-closure pattern already used for the poll path and the enroll fan-out, so no new cross-context internal import is introduced. The cross-context composition happens at `server/cmd/fleet-edr-server/main.go`, where the gateway listener is mounted alongside the existing HTTP routes.

## Explicitly out of scope

- NATS (or any) routing backplane for cross-gateway fan-out at scale.
- Interactive RTR / live shell. This connection is built as its substrate; the RTR frames and session semantics are a later change.
- mTLS and hardware-bound (Secure Enclave) agent identity.
- A separate `fleet-edr-gateway` binary for the distributed profile. The gateway is embedded in the server binary for now.
