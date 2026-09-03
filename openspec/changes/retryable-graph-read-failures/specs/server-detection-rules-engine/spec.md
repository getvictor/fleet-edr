# Server detection rules engine

## MODIFIED Requirements

### Requirement: Rule failure isolation, batch retry on persistence failure

The system SHALL isolate a single rule's evaluation failure so that other rules in the batch still run, EXCEPT where the failure means the rule's dependency was unavailable rather than that the rule was wrong: a failed READ of the process graph SHALL fail the batch with the retryable error class, so the processor re-evaluates those events rather than acknowledging them. The system MUST NOT silently drop alerts on persistence failures: when persisting a finding fails, the batch is surfaced as failed so the processor can retry it.

Isolation and retry are the right handling of two different conditions, and treating them alike loses detections silently. A BROKEN rule must be isolated: retrying cannot change its answer, and failing the batch on it would let one defective rule stop detection for every other rule. A rule whose graph read FAILED is not broken. The answer is merely unavailable, the events are still in the work queue, and every rule in that batch that reads the graph is equally affected, so isolating one of them and acknowledging the batch discards the evaluation of all of them.

A graph read failure SHALL fail the batch regardless of which rule performed the read, and no rule SHALL be required to classify the failure itself for this to hold. A contract that depends on each rule remembering to mark its own read failures retryable is one an added rule silently breaks, and the resulting loss is invisible.

A failed read SHALL be distinguished from a read that legitimately finds nothing. An absent row is an answer, and rules already handle it; only the failure to obtain an answer is retryable.

A failed read SHALL be distinguishable from a rule that is deliberately waiting. Both are retryable, and they diverge in one place: a waiting rule's error is absorbed per event so the batch continues, because one undecidable event must not mask the rest, whereas a failed read SHALL be propagated at once. The next event's read reaches the same unavailable dependency, so continuing multiplies one outage by the batch size for no gain.

Propagating a failed read SHALL NOT discard the findings the rule had already resolved from earlier events in the batch. Those findings SHALL be reported alongside the retryable error and persisted, as they are for any other retryable error. A batch that keeps failing is eventually set aside and nothing re-derives them, so discarding them loses detections outright rather than delaying them.

A failed read SHALL NOT stop the batch's remaining rules. The reads a rule performs span more than one dependency: the process and exec-chain lookups and the event-archive lookups are backed independently, so one being unavailable says nothing about the other. Stopping the batch would skip rules that could have decided, and once the batch is set aside their detections are lost rather than late.

A failed read SHALL NOT be reported once per attempt. The processing cadence makes that a continuous stream of records for as long as the condition lasts, which is the log amplification that reporting a deliberate wait quietly already exists to avoid. It SHALL be surfaced by consequence instead: a retry that succeeds costs nothing and needs no report, and when retries are exhausted the record of the events being set aside SHALL name the failure that caused it, so the case that costs detections is both loud and diagnosable.

The retry this creates SHALL be bounded by the work queue's own bound rather than left open-ended, so that a read which fails permanently (as opposed to transiently) cannot hold its host's queue forever. The "A batch that cannot be processed does not stall its host" requirement of the server-event-ingestion capability is what supplies that bound.

#### Scenario: One rule errors during evaluation

- **GIVEN** a batch where one registered rule's evaluation returns an error unrelated to reading the process graph
- **WHEN** the engine processes the batch
- **THEN** the error is recorded and the engine continues evaluating the remaining rules
- **AND** the remaining rules' findings are persisted normally

#### Scenario: A failed process-graph read retries the batch instead of acknowledging it

- **GIVEN** a batch being evaluated while a read of the process graph fails
- **WHEN** a rule performs that read
- **THEN** evaluation fails with the retryable error class
- **AND** the processor does not acknowledge the batch, so the events are re-evaluated on a later cycle
- **AND** the events are not lost to a warning log

#### Scenario: A failed read stops that rule's pass over the batch rather than repeating itself per event

- **GIVEN** a rule evaluating a batch of many events while its reads fail
- **WHEN** the first read fails
- **THEN** that rule stops rather than repeating the failing read for every remaining event

#### Scenario: A failed read keeps the findings already resolved

- **GIVEN** a rule that resolved a finding from an earlier event in the batch, then hit a failed read
- **WHEN** the failure is reported
- **THEN** the finding is reported alongside it and persisted
- **AND** a rule that failed for a reason other than a read still has its findings discarded, since its output is not trustworthy

#### Scenario: A failed read does not stop the batch's other rules

- **GIVEN** a batch and several rules, where one rule's read fails
- **WHEN** evaluation continues
- **THEN** the rules after it are still evaluated, because they may read a dependency that is healthy
- **AND** the batch is still retried

#### Scenario: A failed read is surfaced by consequence, not per attempt

- **GIVEN** rule evaluation failing because a read failed
- **WHEN** the batch is returned for retry
- **THEN** the attempt is not reported at a level that would produce a record per retry for the duration of the condition
- **AND** it is not counted as a process-materialization retry, which is a different condition
- **AND** when retries are exhausted, the record of the events being set aside names the underlying failure

#### Scenario: A read that finds nothing is not a failure

- **GIVEN** a batch being evaluated while the process graph is healthy
- **WHEN** a rule's read matches no row
- **THEN** the absence is returned to the rule as an answer rather than as a retryable failure
- **AND** the batch is acknowledged normally

#### Scenario: An alert persistence write fails

- **GIVEN** a finding that the engine attempts to persist
- **WHEN** the persistence layer returns an error
- **THEN** the engine signals the failure to its caller so the entire batch is retried on a future cycle
- **AND** the failed finding is not silently discarded
