# Observability instrumentation

## ADDED Requirements

### Requirement: Per-rule evaluation cost is recorded durably

The system SHALL record, durably and per rule, how many times each rule evaluated, how long those evaluations took, and how many ended in a retryable outcome rather than a decision, so that an operator can find the expensive rule and the churning rule in the product rather than only in a metrics backend.

This is a different question from how often a rule matches, and a rule's match count cannot answer it: a rule can be perfectly quiet and still be the one holding up the drain loop. The existing per-rule latency lives only on the evaluation span, which is exactly the backend an operator should not have to query, and the retry counter is fleet-wide and so cannot name the rule responsible.

Recording SHALL count evaluation ATTEMPTS, and SHALL happen whether or not the batch is acknowledged.

That is deliberately the opposite of the rule the "Monitor-mode matches are recorded durably per rule" requirement sets for match counts, and both are correct because they count different things. A monitor match is a fact about the world, that this rule matched this host on that day, so a replayed batch must not record it twice. An evaluation is a fact about work the system performed, and a replayed batch genuinely did evaluate again. Counting attempts also leaves the derived figures intact, because the attempt count and the total time inflate by the same replay factor and the mean they produce together does not move. Recording only on acknowledgement would additionally put the retryable-outcome count out of reach, because a batch that ends in a retryable outcome is never acknowledged, and naming the rule behind the retry churn is the reason that count exists.

An evaluation SHALL be counted only when the rule was actually given events to evaluate. A rule the platform scope left with nothing to see did not run, and counting it would report work that never happened and drag that rule's measured cost toward zero.

A failure to record SHALL NOT fail the batch, and SHALL NOT nack a batch that has already been acknowledged.

Recorded statistics SHALL be bounded by the number of rules and the deployment's data-retention window rather than by event volume, and pruning them SHALL NOT require a leader-elected task, for the same reason the match counts' prune does not.

#### Scenario: Statistics outlive the process that produced them

- **GIVEN** a rule that has evaluated, with its statistics recorded
- **WHEN** the process restarts, or another replica serves the read
- **THEN** the recorded statistics are still reported rather than starting from zero

#### Scenario: A replayed batch counts each attempt, and records the retryable outcome

- **GIVEN** a batch whose evaluation ends in a retryable outcome, so the batch is nacked and replayed
- **WHEN** each attempt evaluates the same rule
- **THEN** every attempt is counted, with its own duration
- **AND** the retryable outcome is recorded even though the batch was never acknowledged

#### Scenario: A rule with nothing in scope is not counted as having evaluated

- **GIVEN** a batch carrying only events outside a rule's target platform
- **WHEN** the batch is evaluated
- **THEN** that rule has no recorded evaluation, rather than one of zero duration

#### Scenario: A recording failure does not fail the batch

- **GIVEN** a batch whose evaluation statistics cannot be persisted
- **WHEN** the recording fails
- **THEN** the failure is logged
- **AND** the batch's own outcome is unchanged and its events are not replayed on account of it

#### Scenario: Statistics older than the retention window are pruned

- **GIVEN** recorded statistics older than the configured retention window
- **WHEN** the prune runs
- **THEN** those statistics are deleted
- **AND** statistics inside the window are kept
