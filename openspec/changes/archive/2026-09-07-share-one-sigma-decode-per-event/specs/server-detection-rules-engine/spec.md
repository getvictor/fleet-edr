# Detection rules engine

## ADDED Requirements

### Requirement: Rules evaluating one batch derive shared work once

The engine SHALL offer every rule evaluating one batch the same per-batch scratch space, so that rules deriving the same thing from the same events derive it once rather than once each.

The scratch space SHALL be opaque to the engine, which SHALL NOT depend on what any rule derives into it. It SHALL live for exactly one batch evaluation, so that no derived value survives a request and concurrent batch evaluations share nothing.

Using it SHALL be optional. A rule that derives nothing shareable SHALL be evaluated unchanged, and a rule SHALL produce the same findings whether or not it is given a scope.

Work derived through the scratch space SHALL be shared only where sharing is observationally equivalent. In particular, an error from a deferred lookup SHALL reach only the rules that requested that lookup, because such an error discards the requesting rule's findings for the whole batch and must not discard those of a rule that never made the request.

#### Scenario: Every rule in one batch is offered the same scope

- **GIVEN** two rules that both derive a value from the batch under the same key
- **WHEN** the engine evaluates one batch containing an event both rules consume
- **THEN** the second rule receives the value the first derived, rather than deriving it again

#### Scenario: A later batch does not see an earlier batch's derivations

- **GIVEN** a rule that derives a value from the batch
- **WHEN** the engine evaluates a second batch
- **THEN** the rule derives the value again, because the scratch space did not outlive the first batch

#### Scenario: A rule that does not use the scope is unaffected

- **GIVEN** a registered rule that derives nothing from the batch
- **WHEN** the engine evaluates a batch it consumes
- **THEN** the rule is evaluated and its findings are collected as before

#### Scenario: One event is decoded once however many rules read it

- **GIVEN** several Sigma-backed rules that all read fields of the same event
- **WHEN** the engine evaluates the batch containing it
- **THEN** the event's payload is decoded once and its process-graph lookups are performed once

#### Scenario: A failed lookup reaches only the rule that asked for it

- **GIVEN** two Sigma-backed rules reading the same event, where only one reads a field resolved from the process graph, and that lookup fails
- **WHEN** the engine evaluates the batch
- **THEN** the rule that read the field reports the failure and the rule that did not is unaffected

### Requirement: An event a rule cannot identify a subject for is skipped

A rule SHALL skip an event whose payload does not decode, or which carries no process identifier, rather than acting on it or failing the batch.

Such an event cannot be attributed to a process, so there is nothing for a finding to name, and it SHALL NOT be treated as an error: an error from a rule's per-event evaluation discards the findings that rule has already collected from the rest of the batch, so one malformed event from one host would cost every other alert in the batch.

#### Scenario: A malformed event does not discard the batch's findings

- **GIVEN** a batch containing an event whose payload does not decode, followed by an event a rule fires on
- **WHEN** the rule evaluates the batch
- **THEN** the malformed event is skipped and the finding from the later event is still produced

#### Scenario: An event carrying no process identifier is skipped rather than attributed to process zero

- **GIVEN** an event whose payload omits the process identifier
- **WHEN** a rule evaluates it
- **THEN** the event is skipped, rather than a process lookup being performed for identifier zero
