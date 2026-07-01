## 1. Spec delta and decision

- [x] 1.1 This proposal plus spec deltas pass `openspec validate push-command-channel --strict`
- [x] 1.2 Amend `docs/adr/0010-stateless-server.md` to name the control gateway as the sanctioned stateful tier (live connections only, nothing durable, losable on reconnect without command loss); keep the `server-availability` modified requirement in lockstep

## 2. Control-channel transport contract

- [x] 2.1 Define the bidirectional stream frame contract: command frames down (`id`, `host_id`, `command_type`, `payload`), outcome frames up (`id`, `status`, `result`), using the same field shapes as the `commands` row and the `PUT /api/commands/{id}` body so the wire shape is byte-stable across transports
- [x] 2.2 Property-based round-trip test for the frame encoding (`Marshal then Unmarshal == identity`)
- [x] 2.3 Promote gRPC + protobuf from indirect to direct dependencies; add `otelgrpc` stats handlers so W3C trace context propagates over stream metadata

## 3. Server gateway (embedded in fleet-edr-server, response context)

- [x] 3.1 Connect-time auth interceptor: verify the signed host token from stream metadata via the existing `endpoint` verify + revocation snapshot (no DB round-trip), pin `host_id` into the stream context, reject otherwise; surface a snapshot blip as retryable, not a hard deauth
- [x] 3.2 Connection registry: live connections keyed by `host_id`, each holding its auth metadata (token epoch + expiry) and an in-flight-command-id set (in-memory, per-replica, documented "safe to lose" per ADR-0010). Enforce at most one connection per host: on a new connection for an already-connected host, close and release the prior connection before registering the new one (no leaked goroutine/fd, no duplicate push)
- [x] 3.3 MySQL watch loop: every fixed 1s interval read pending commands scoped to locally-held hosts (`WHERE status='pending' AND host_id IN (<connected ids>)`, batched if the connected set is large) so the query seeks the `(host_id, status)` index instead of scanning the whole pending backlog; push each row, skipping IDs already in flight on that connection
- [x] 3.4 In-process fast path: when a command is queued on this replica for a locally-held connection, notify the gateway and push immediately without waiting for the watch tick
- [x] 3.5 Outcome frames call the unchanged `response.api.Service.UpdateStatus` (same state machine); an outcome that is not a valid transition for the command's current status is rejected and the agent treats it as already-handled, not an error
- [x] 3.6 Liveness: bump `host.last_seen_ns` on connect and on the keep-alive cadence via the injected `detection` host-seen closure; reflect disconnect as offline
- [x] 3.7 Revocation teardown: on the revocation-snapshot refresh cadence, close any held connection whose token no longer validates (revoked epoch or expiry), within the propagation bound
- [x] 3.8 Mount the gateway listener in `server/cmd/fleet-edr-server/main.go` alongside the HTTP routes; the gateway is embedded, no new binary

## 4. Agent control client

- [x] 4.1 Open the stream over the existing pinned-TLS shared transport, presenting the current host token in connect metadata; reconnect with exponential backoff + jitter on drop or connect failure
- [x] 4.2 Reconnect with the fresh token after the proactive token refresh, rather than an in-band re-auth frame
- [x] 4.3 Dispatch pushed commands through the same executor handlers as the poll path (kill, set-application-control, unknown-type), idempotent by command id; record each command's final outcome and, on re-delivery of an already-executed command, re-report the recorded outcome instead of re-executing (prevents a lost report stranding the command in pending and a `kill_process` re-run overwriting success with "no such process"); re-report outcomes for in-flight commands on reconnect
- [x] 4.4 Prefer the stream when up and suppress the command poll; resume the existing 5s poll when the stream is unavailable so commands still flow on the degraded floor
- [x] 4.5 Keep-alive probes detect a silently-dropped connection and trigger reconnect rather than going dark

## 5. Tests

- [x] 5.1 Integration (real MySQL): a command queued for a connected fake agent is pushed and acked over the stream, transitioning pending -> acked -> completed identically to the poll path
- [x] 5.2 Cross-host isolation: host A's connection never receives host B's commands; an outcome frame for another host's command is rejected
- [x] 5.3 Duplicate delivery: the same command offered twice runs its side effect once; a re-delivery after a lost completion report re-reports the recorded outcome and transitions the command out of pending (not a silent no-op, not a re-execution)
- [x] 5.4 Duplicate connection: a reconnect for an already-connected host closes the prior connection (no leaked connection, no double push), and the new connection is the sole channel
- [x] 5.5 Revocation: a revoked token closes the connection within the propagation bound; the agent must re-authenticate to reconnect
- [x] 5.6 Fallback: with the gateway unreachable the agent resumes polling and commands are still delivered and reported
- [x] 5.7 Liveness: a connected host's last-seen advances without a poll or upload; disconnect flips it offline

## 6. QA

- [ ] 6.1 Verify end to end on the dev server plus a live agent (edr-dev): queue a kill from the UI and confirm sub-second delivery over the stream and the offline/online flip on disconnect; confirm trace continuity across the stream in SigNoz
