# server-detection-rules-engine delta

## ADDED Requirements

### Requirement: Retryable evaluation on unmaterialized flow process

The system MUST NOT silently drop a `dns_c2_beacon` alert because the rule evaluated a `network_connect` before a concurrently processed batch committed the connecting process's row (intra-replica processor workers and cross-replica claimers both create this window). When the rule resolves the flow's process and the lookup misses while the connect's ingest age is inside a fixed flow-materialization grace window, evaluation SHALL fail the batch with the retryable not-yet-materialized error class so the processor does not acknowledge the events and re-evaluates them on a later cycle, by which time the concurrent flush has committed. Once the connect is older than the grace window, a missing flow process SHALL be treated as permanently absent (its exec was never delivered) and the connect evaluated without a finding, so an orphaned connect cannot hold its batch in a retry loop.

This flow-process grace window MUST be materially tighter than the subject-process materialization grace, because flow resolution runs before the rule's suspicion gate and so is reachable by any outbound connect rather than only a pre-filtered event; the tighter bound caps the batch-retry cost a genuinely orphaned connect can incur under sustained load while still covering the ordering race, which commits within a batch flush.

#### Scenario: A young outbound connect's flow process row is missing

- **GIVEN** an outbound `network_connect` whose connecting process has no materialized process row
- **AND** the connect was ingested more recently than the flow-materialization grace window
- **WHEN** the `dns_c2_beacon` rule evaluates it
- **THEN** evaluation fails with the retryable not-yet-materialized error class
- **AND** the processor does not acknowledge the batch, so the events are re-evaluated on a later cycle
- **AND** the alert is produced by the re-evaluation once the process row is committed

#### Scenario: An outbound connect past the grace window has no flow process row

- **GIVEN** an outbound `network_connect` whose connecting process has no materialized process row
- **AND** the connect was ingested longer ago than the flow-materialization grace window
- **WHEN** the `dns_c2_beacon` rule evaluates it
- **THEN** the connect produces no finding and no error
- **AND** the batch is acknowledged normally
