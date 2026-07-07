# server-process-graph-builder delta

## ADDED Requirements

### Requirement: Re-processing a batch is idempotent

The graph builder MUST be idempotent under re-processing: applying the same batch of fork/exec/exit/snapshot/heartbeat events more than once SHALL yield the identical process forest as applying it once, with no duplicate generations, no fabricated re-exec generations, no phantom PID-reuse closes, and no freshness regressions. This is required because the detection processor nacks and re-claims a batch on a retryable evaluation miss, and a claim-lease-expiry re-offer can replay a stalled or crashed worker's events, so the same events are folded through the builder more than once. Idempotency is anchored on the event that materialized each row: a row records the id of the event that created it and the id of the event that applied its current exec image and its exit, and the builder skips an event whose effect is already recorded. An observed exit MUST NOT close a process that forked after the exit, and a heartbeat's freshness bump MUST only advance (never move backward), so a replayed exit or heartbeat cannot corrupt a later generation of a reused PID that a prior pass already materialized.

#### Scenario: Re-applying the same batch yields the same forest

- **GIVEN** a batch of fork/exec/exit/snapshot/heartbeat events that the builder has already processed once, materializing a process forest
- **WHEN** the identical batch is processed a second time (a nack-and-re-claim, or a claim-lease-expiry re-offer)
- **THEN** the process forest is unchanged: the same rows, the same generations and re-exec chain, and the same exit and freshness state
- **AND** no duplicate process rows, fabricated re-exec generations, or phantom PID-reuse closes are created
