# Server detection rules engine: a rule's evaluation time is bounded delta

## ADDED Requirements

### Requirement: A rule that repeatedly exceeds its evaluation budget stops being evaluated

The system SHALL bound how long one rule may take to evaluate one batch, and SHALL stop evaluating a rule that exceeds that bound repeatedly rather than continuing to pay it on every batch.

This exists because estimating a pattern's cost cannot bound the cost of an evaluation. Bounds on authored patterns are proxies, and they deliberately leave the event side unbounded: a field's values are compared against every value an event supplies, and comparing one costs in proportion to the event's own string. Measuring the evaluation is the only thing that bounds the product.

Exceeding the budget SHALL NOT be reported as a rule failure. A failing rule causes the batch to be replayed, so a slow rule reporting failure would be retried into the same slow rule on every attempt, which is the stalled-host condition the queue's retry bound exists to prevent, reached by a different route. An overrun SHALL be recorded, the findings the evaluation already produced SHALL be kept, and the batch SHALL continue.

A rule SHALL be skipped only after exceeding the budget repeatedly AND over a period, never on a single overrun. One slow evaluation is not evidence: a cold cache, an unusually large batch, or a host that has just enrolled each produce one, and a rule doing legitimate work has been measured taking two orders of magnitude longer than the mean without being unaffordable.

Skipping SHALL NOT change the rule's configured mode, or what the system reports that mode to be. A mode is what an operator asked for and a skip is what the system is doing to protect itself; reporting one as the other misrepresents the operator's intent and leaves unclear who may undo it.

The skip SHALL be local to the replica that measured it and SHALL NOT outlive the process. Each replica protects itself against the load it actually sees, and a heuristic that survives a restart keeps punishing a rule for a condition that may have passed.

Skipping SHALL be observable as a counter and as a log record naming the rule and what it measured. A rule that has stopped being evaluated raises no alerts, which is indistinguishable from a rule that matches nothing, so the condition has to be reported rather than inferred.

The budget SHALL be set from measured evaluation times rather than chosen, and SHALL leave room above the slowest rule doing legitimate work.

#### Scenario: A rule over budget on one batch is still evaluated on the next

- **GIVEN** a rule whose evaluation exceeds the budget once
- **WHEN** the next batch is processed
- **THEN** the rule is evaluated again

#### Scenario: A rule repeatedly over budget stops being evaluated

- **GIVEN** a rule that exceeds the budget on many batches over a period
- **WHEN** the bounds are both exceeded
- **THEN** the rule is no longer evaluated on that replica
- **AND** a counter and a log record name the rule and what it measured

#### Scenario: An overrun does not cause the batch to be replayed

- **GIVEN** a rule whose evaluation exceeds the budget
- **WHEN** the batch finishes
- **THEN** the batch is not replayed on account of the overrun
- **AND** any findings that evaluation produced are kept

#### Scenario: A skipped rule reports its configured mode unchanged

- **GIVEN** a rule the system has stopped evaluating for exceeding its budget
- **WHEN** the rule catalog is read
- **THEN** it reports the mode the operator configured, not a disabled one

#### Scenario: The other rules are unaffected

- **GIVEN** one rule being skipped for exceeding its budget
- **WHEN** a batch is processed
- **THEN** every other rule is evaluated as usual
