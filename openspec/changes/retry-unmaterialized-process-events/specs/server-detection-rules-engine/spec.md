# server-detection-rules-engine delta

## ADDED Requirements

### Requirement: Retryable evaluation on unmaterialized subject process

The system MUST NOT silently drop an alert because rule evaluation ran before a concurrently processed batch committed the event's subject process row (intra-replica processor workers and cross-replica claimers both create this window). When a rule resolves the process an event is about (the pid carried in the event's own payload) and the lookup misses while the event's ingest age is inside a fixed materialization grace window, evaluation SHALL fail the batch with a retryable error class so the processor does not acknowledge the events and re-evaluates them on a later cycle. Once an event is older than the grace window, a missing subject process SHALL be treated as permanently absent and the event evaluated without a finding, so an orphaned event cannot hold its batch in a retry loop. The retry contract applies only to subject-process lookups: ancestor and parent-chain lookups, and flow-to-process resolution that runs before a suspicion gate, keep the skip semantics.

#### Scenario: A young event's subject process row is missing

- **GIVEN** an event whose payload references a pid with no materialized process row
- **AND** the event was ingested more recently than the materialization grace window
- **WHEN** a rule that resolves that event's subject process evaluates it
- **THEN** evaluation fails with the retryable not-yet-materialized error class
- **AND** the processor does not acknowledge the batch, so the events are re-evaluated on a later cycle
- **AND** the alert is produced by the re-evaluation once the process row is committed

#### Scenario: An event past the grace window has no subject process row

- **GIVEN** an event whose payload references a pid with no materialized process row
- **AND** the event was ingested longer ago than the materialization grace window
- **WHEN** a rule that resolves that event's subject process evaluates it
- **THEN** the event produces no finding and no error
- **AND** the batch is acknowledged normally
