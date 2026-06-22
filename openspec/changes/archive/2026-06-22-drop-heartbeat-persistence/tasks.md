# Drop snapshot_heartbeat persistence: tasks

## 1. Store

- [ ] `processes.go`: add `BumpSnapshotLastSeenBatch(ctx, hostID, []heartbeat{pid, tsNs})` that applies the live-snapshot-scoped `last_seen_ns` UPDATE for each heartbeat in one transaction. Reuse the existing `UpdateLastSeenForSnapshot` predicate so the freshness scoping is identical.

## 2. Intake

- [ ] `handler.go`: in `handleIngest`, partition the parsed batch into heartbeats and the rest. Persist only the rest via `InsertEvents`. Apply the freshness bump for heartbeats via the new store method. Pass the full batch to `UpsertHosts` (host liveness unchanged). Decode the heartbeat PID from the payload; a heartbeat with an unparseable payload or missing pid is skipped (not an error).
- [ ] `handler.go`: keep the `accepted` count reporting the full batch length (the agent's contract is unchanged: every event it sent was accepted).

## 3. Observability

- [ ] `detection/api` `MetricsRecorder`: add `EventsHeartbeatDropped(ctx, hostID string, n int)`.
- [ ] `metrics.go`: `edr.ingest.heartbeats_dropped` counter + method.
- [ ] `handler.go`: emit the counter with the heartbeat count per request.

## 4. Spec

- [ ] `server-event-ingestion` delta: MODIFIED "Authenticated batch event submission" (liveness-only events are processed for their side effect, not persisted as retained rows); ADDED "Liveness heartbeats are processed but not persisted".
- [ ] `server-process-graph-builder` delta: MODIFIED "Snapshot heartbeat events extend the freshness window" (the freshness bump is applied at ingest and the heartbeat is not stored as a retained event; the graph-builder path remains only for pre-upgrade rows).

## 5. Docs

- [ ] `docs/operations.md`: document `EDR_PROCESS_RECONCILE_INTERVAL` as the heartbeat-volume lever and note heartbeats are no longer retained as event rows.

## 6. Tests

- [ ] Intake handler test: a batch mixing heartbeats and real events persists only the real events; `accepted` equals the full count; the heartbeat metric counts the heartbeats.
- [ ] Integration test (real MySQL): heartbeat bumps `last_seen_ns` on a live snapshot row at ingest; no `events` row is created for the heartbeat; a heartbeat for an exited / non-snapshot / unknown PID is a no-op; TTL reconciler still exempts a freshly-heartbeated snapshot row. Scenario markers on the tests.

## 7. Verification

- [ ] `go build ./server/...`; `go test ./server/detection/...`; `go test -tags integration ./server/detection/internal/tests/...` green.
- [ ] gofmt, `task lint:go`, spectrace, markdown + dash lints, `openspec validate drop-heartbeat-persistence --strict`.
- [ ] Dev-server + edr-dev VM: confirm no new `snapshot_heartbeat` rows in `events`, `last_seen_ns` advancing, `edr.ingest.heartbeats_dropped` climbing in SigNoz.
