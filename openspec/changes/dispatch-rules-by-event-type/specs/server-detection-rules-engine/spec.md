# Server detection rules engine: a rule is invoked only for the events it consumes delta

## ADDED Requirements

### Requirement: A rule is invoked only for batches carrying an event type it consumes

The system SHALL evaluate a rule against a batch only when that batch carries at least one event of a type the rule declares it consumes, so that the cost of a batch depends on the rules that can act on it rather than on the size of the catalog.

A rule's declared event types SHALL act as a trigger filter and not as a batch filter: a rule that is invoked SHALL receive the whole batch, because a rule triggered by one event type may read another from the same batch to build its finding. Narrowing the batch to the triggering type would silently degrade those rules.

The system SHALL invoke a rule that declares no event types for every batch. Skipping a rule that had something to do loses a detection with no error and no alert, whereas invoking one that had nothing to do costs only time, so the engine SHALL resolve this asymmetry in favour of running the rule.

Dispatch SHALL preserve the order in which rules were registered, because the engine reports the first retryable error it encounters and reordering would change which rule is named to the operator.

#### Scenario: A rule is not invoked for a batch it cannot act on

- **GIVEN** a rule that declares it consumes only one event type
- **WHEN** a batch arrives carrying none of that type
- **THEN** the rule is not invoked, and no span is recorded for it

#### Scenario: A triggered rule still sees the whole batch

- **GIVEN** a rule triggered by one event type that reads a second type to build its finding
- **WHEN** a batch carrying both arrives
- **THEN** the rule receives every event in the batch, not only those of the triggering type

#### Scenario: A rule declaring no event types still runs

- **GIVEN** a registered rule that declares no event types
- **WHEN** any batch is evaluated
- **THEN** the rule is invoked, because dispatch is an optimisation and must not drop a detection

### Requirement: A rule declares the event types it consumes

Every registered rule SHALL declare at least one event type, and each declared type SHALL be one the agent actually emits. A rule declaring nothing forfeits dispatch, and one declaring a type that is never emitted would never be invoked at all.

A rule's declaration SHALL cover every event type it reads. A rule that reads a type it does not declare would be skipped for batches carrying only that type, and the findings it would have produced are lost silently, so the declaration is verified against the rule's behaviour rather than trusted.

#### Scenario: A rule that declares no event types is refused

- **GIVEN** a registered rule whose declaration names no event type
- **WHEN** the catalog is checked
- **THEN** it fails, naming the rule

#### Scenario: A rule finds nothing in a batch of types it does not declare

- **GIVEN** a registered rule and a batch made entirely of event types it does not declare
- **WHEN** the rule evaluates that batch
- **THEN** it produces no findings, so skipping it for such a batch loses nothing

### Requirement: A rule that does not run records no span

The system SHALL determine that a rule has nothing to evaluate before opening that rule's span, so that per-rule spans describe work that actually happened. A span emitted for a rule that was handed no events reports evaluation that did not occur and inflates per-rule span volume by every rule the batch could never reach.

A rule that IS evaluated SHALL still carry its span with the rule identifier and the resulting alert count, because those attributes are what let detection latency and alert volume be grouped by rule.

#### Scenario: A rule scoped out by platform records no span

- **GIVEN** a rule targeting a platform no event in the batch carries
- **WHEN** the batch is evaluated
- **THEN** no span is recorded for that rule
