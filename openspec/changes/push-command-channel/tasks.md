## 1. Spec delta and decision

- [ ] 1.1 This proposal plus spec deltas pass `openspec validate push-command-channel --strict`
- [ ] 1.2 Amend `docs/adr/0010-stateless-server.md` to name the control gateway as the sanctioned stateful tier (live connections only, nothing durable, losable on reconnect without command loss); keep the `server-availability` modified requirement in lockstep

## 2. Control-channel transport contract

- [ ] 2.1 Define the bidirectional stream frame contract: command frames down (`id`, `host_id`, `command_type`, `payload`), outcome frames up (`id`, `status`, `result`), using the same field shapes as the `commands` row and the `PUT /api/commands/{id}` body so the wire shape is byte-stable across transports
- [ ] 2.2 Property-based round-trip test for the frame encoding (`Marshal then Unmarshal == identity`)
- [ ] 2.3 Promote gRPC + protobuf from indirect to direct dependencies; add `otelgrpc` stats handlers so W3C trace context propagates over stream metadata

## 3. Server gateway (embedded in fleet-edr-server, response context)

- [ ] 3.1 Connect-time auth interceptor: verify the signed host token from stream metadata via the existing `endpoint` verify + revocation snapshot (no DB round-trip), pin `host_id` into the stream context, reject otherwise; surface a snapshot blip as retryable, not a hard deauth
- [ ] 3.2 Connection registry: live connections keyed by `host_id`, with a per-connection in-flight-command-id set (in-memory, per-replica, documented "safe to lose" per ADR-0010)
- [ ] 3.3 MySQL watch loop: every fixed 1s interval read pending commands and push each row whose `host_id` is locally held, skipping IDs already in flight on that connection
- [ ] 3.4 In-process fast path: when a command is queued on this replica for a locally-held connection, notify the gateway and push immediately without waiting for the watch tick
- [ ] 3.5 Outcome frames call the unchanged `response.api.Service.UpdateStatus` (same state machine); an invalid transition on a re-delivered command is treated as already-handled, not an error
- [ ] 3.6 Liveness: bump `host.last_seen_ns` on connect and on the keep-alive cadence via the injected `detection` host-seen closure; reflect disconnect as offline
- [ ] 3.7 Revocation teardown: on the revocation-snapshot refresh cadence, close any held connection whose token no longer validates (revoked epoch or expiry), within the propagation bound
- [ ] 3.8 Mount the gateway listener in `server/cmd/fleet-edr-server/main.go` alongside the HTTP routes; the gateway is embedded, no new binary

## 4. Agent control client

- [ ] 4.1 Open the stream over the existing pinned-TLS shared transport, presenting the current host token in connect metadata; reconnect with exponential backoff + jitter on drop or connect failure
- [ ] 4.2 Reconnect with the fresh token after the proactive token refresh, rather than an in-band re-auth frame
- [ ] 4.3 Dispatch pushed commands through the same executor handlers as the poll path (kill, set-application-control, unknown-type), idempotent by command id; report ack/complete/fail over the stream
- [ ] 4.4 Prefer the stream when up and suppress the command poll; resume the existing 5s poll when the stream is unavailable so commands still flow on the degraded floor
- [ ] 4.5 Keep-alive probes detect a silently-dropped connection and trigger reconnect rather than going dark

## 5. Tests

- [ ] 5.1 Integration (real MySQL): a command queued for a connected fake agent is pushed and acked over the stream, transitioning pending -> acked -> completed identically to the poll path
- [ ] 5.2 Cross-host isolation: host A's connection never receives host B's commands; an outcome frame for another host's command is rejected
- [ ] 5.3 Duplicate delivery: the same command offered twice executes exactly once (second delivery is a no-op)
- [ ] 5.4 Revocation: a revoked token closes the connection within the propagation bound; the agent must re-authenticate to reconnect
- [ ] 5.5 Fallback: with the gateway unreachable the agent resumes polling and commands are still delivered and reported
- [ ] 5.6 Liveness: a connected host's last-seen advances without a poll or upload; disconnect flips it offline

## 6. QA

- [ ] 6.1 Verify end to end on the dev server plus a live agent (edr-dev): queue a kill from the UI and confirm sub-second delivery over the stream and the offline/online flip on disconnect; confirm trace continuity across the stream in SigNoz
