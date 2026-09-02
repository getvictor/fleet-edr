# Detection rules engine

## ADDED Requirements

### Requirement: A rule whose identifier cannot be persisted is refused at load

Every surface that stores a rule identifier SHALL accept the full length the system permits a rule identifier to be, and that permitted length SHALL be defined in one place that both the storage and the validation agree on.

A rule whose identifier exceeds the permitted length SHALL be refused when the rule set is loaded, and the refusal SHALL name the rule and the limit. It SHALL NOT be registered, and it SHALL NOT be presented to an operator as a rule they can configure or promote.

Refusing at load rather than discovering the problem at write time is the point of this requirement. A rule whose identifier is too long for the alert table cannot raise an alert, and the failure does not degrade gracefully: persisting an alert is not isolated per rule, so the error fails the batch, the batch is nacked and re-claimed, and nothing caps the attempts. A single such rule matching on a host therefore stops that host's event queue from draining at all, which ends detection for that host rather than for that rule. Presenting such a rule as promotable offers the operator an action whose consequence is a detection outage.

The identifier's permitted length SHALL leave headroom above the longest identifier the system ships, so that importing an upstream rule corpus does not require a schema change, and the refusal SHALL be the mechanism that catches an identifier beyond that headroom.

#### Scenario: An over-long identifier is refused when the rule set loads

- **GIVEN** a rule whose identifier is longer than the permitted length
- **WHEN** the rule set is loaded
- **THEN** loading fails with an error naming that rule and the limit
- **AND** the rule is not registered

#### Scenario: Every shipped rule identifier is storable

- **GIVEN** the rule set the system ships
- **WHEN** each rule's identifier is measured against the permitted length
- **THEN** every identifier is within it

#### Scenario: A rule with a long identifier can raise an alert

- **GIVEN** a rule in alert mode whose identifier is longer than 64 characters
- **WHEN** the rule matches an ingested event
- **THEN** the alert is persisted and readable
- **AND** the batch is acknowledged rather than nacked and replayed
