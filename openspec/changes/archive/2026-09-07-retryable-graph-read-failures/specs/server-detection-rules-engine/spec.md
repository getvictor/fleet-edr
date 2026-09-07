# Server detection rules engine

## MODIFIED Requirements

### Requirement: Rule failure isolation, batch retry on persistence failure

The system SHALL isolate a single rule's evaluation failure so that other rules in the batch still run, EXCEPT where the failure means the rule's dependency was unavailable rather than that the rule was wrong: a failed READ of the process graph SHALL fail the batch with the retryable error class, so the processor re-evaluates those events rather than acknowledging them. The system MUST NOT silently drop alerts on persistence failures: when persisting a finding fails, the batch is surfaced as failed so the processor can retry it.

Isolation and retry are the right handling of two different conditions, and treating them alike loses detections silently. A BROKEN rule must be isolated: retrying cannot change its answer, and failing the batch on it would let one defective rule stop detection for every other rule. A rule whose graph read FAILED is not broken. The answer is merely unavailable, the events are still in the work queue, and every rule in that batch that reads the graph is equally affected, so isolating one of them and acknowledging the batch discards the evaluation of all of them.

A graph read failure SHALL fail the batch regardless of which rule performed the read, and no rule SHALL be required to classify the failure itself for this to hold. A contract that depends on each rule remembering to mark its own read failures retryable is one an added rule silently breaks, and the resulting loss is invisible.

A failed read SHALL be distinguished from a read that legitimately finds nothing. An absent row is an answer, and rules already handle it; only the failure to obtain an answer is retryable.

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
