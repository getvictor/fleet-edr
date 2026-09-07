# server-detection-rules-engine

## MODIFIED Requirements

### Requirement: Retryable evaluation on unmaterialized flow process

The system MUST NOT silently drop a `dns_c2_beacon` alert because the rule evaluated a `network_connect` before a concurrently processed batch committed the connecting process's row (intra-replica processor workers and cross-replica claimers both create this window). When the rule resolves the flow's process and the lookup misses while the connect's ingest age is inside a fixed flow-materialization grace window, evaluation SHALL fail the batch with the retryable not-yet-materialized error class so the processor does not acknowledge the events and re-evaluates them on a later cycle, by which time the concurrent flush has committed. Once the connect is older than the grace window, a missing flow process SHALL be treated as permanently absent (its exec was never delivered) and the connect evaluated without a finding, so an orphaned connect cannot hold its batch in a retry loop.

This flow-process grace window MUST be materially tighter than the subject-process materialization grace, because flow resolution runs before the rule's suspicion gate and so is reachable by any outbound connect rather than only a pre-filtered event; the tighter bound caps the batch-retry cost a genuinely orphaned connect can incur under sustained load while still covering the ordering race, which commits within a batch flush.

A connect whose flow process is permanently absent MUST NOT prevent the rule from evaluating the remaining events in the same batch. Rule evaluation SHALL continue past a flow-materialization miss and report it only after every event in the batch has been evaluated, returning the findings that did resolve alongside the miss. Returning on the first miss let an orphaned connect (whose row never arrives, so it misses on every retry) hold the rule at that event for the whole of its own grace window; a resolvable beacon later in the same batch was then first evaluated only after its own, tighter grace had already elapsed, at which point a still-uncommitted row degraded to the silent skip and the alert was lost permanently.

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

#### Scenario: An unresolvable event does not mask resolvable findings in the same batch

- **GIVEN** a batch containing an outbound `network_connect` whose connecting process row never materializes
- **AND** the same batch contains a later outbound `network_connect` from a temp-path process that resolved the address it is connecting to
- **WHEN** the `dns_c2_beacon` rule evaluates the batch
- **THEN** the finding for the resolvable connect is produced
- **AND** the unresolvable connect's retryable not-yet-materialized error class is still reported so the batch is re-evaluated

### Requirement: Retryable evaluation on unmaterialized subject process

The system MUST NOT silently drop an alert because rule evaluation ran before a concurrently processed batch committed the event's subject process row (intra-replica processor workers and cross-replica claimers both create this window). When a rule resolves the process an event is about (the pid carried in the event's own payload) and the lookup misses while the event's ingest age is inside a fixed materialization grace window, evaluation SHALL fail the batch with a retryable error class so the processor does not acknowledge the events and re-evaluates them on a later cycle. Once an event is older than the grace window, a missing subject process SHALL be treated as permanently absent and the event evaluated without a finding, so an orphaned event cannot hold its batch in a retry loop. This subject-process retry contract applies to subject-process lookups; ancestor and parent-chain lookups keep the skip semantics. (`dns_c2_beacon`'s flow-to-process resolution, which runs before its suspicion gate, uses an analogous retry under a tighter grace, specified separately by the "Retryable evaluation on unmaterialized flow process" requirement.)

A retryable miss MUST NOT reduce the evaluation any other rule or event receives from the same batch. Specifically: every registered rule SHALL be evaluated against the batch even after an earlier rule reported a miss, and the findings a rule did resolve SHALL be persisted even when that same rule also reported one. The miss SHALL be reported after every rule has run, so the processor still declines to acknowledge the batch. Stopping at the first miss meant a rule waiting on a row that never arrives suppressed every rule registered after it for the whole of its own grace window, and because the grace windows differ per rule, the suppressed rules were first evaluated only after their own (shorter) windows had elapsed, converting a recoverable race into permanent alert loss.

Non-retryable failures keep their existing semantics: an ordinary rule-evaluation error is logged and swallowed so one misbehaving rule cannot wedge the pipeline, and an alert-persistence error aborts the batch immediately.

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

#### Scenario: A retryable miss does not suppress the remaining rules

- **GIVEN** a batch that a rule reports a retryable not-yet-materialized error class for
- **AND** another rule is registered after it
- **WHEN** the engine evaluates the batch
- **THEN** the rule registered after the miss is still evaluated against the batch
- **AND** the retryable error class is still reported so the processor does not acknowledge the batch

#### Scenario: Findings resolved in a batch persist alongside a retryable miss

- **GIVEN** a rule that resolves a finding for one event in a batch and reports a retryable not-yet-materialized error class for another
- **WHEN** the engine evaluates the batch
- **THEN** an alert is persisted for the resolved finding
- **AND** the retryable error class is still reported so the processor does not acknowledge the batch
- **AND** re-evaluation of the batch does not create a duplicate alert for the already-persisted finding
