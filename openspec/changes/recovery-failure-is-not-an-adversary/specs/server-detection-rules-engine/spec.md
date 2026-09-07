# Server detection rules engine: a technique is a claim about what was observed

## MODIFIED Requirements

### Requirement: MITRE ATT&CK technique stamping

The system SHALL stamp each persisted alert with the MITRE ATT&CK technique identifiers declared by the firing rule. The stamped list MUST be preserved on the alert row even if the rule's technique mapping is later refined.

A rule SHALL declare a technique only for something it OBSERVED, not for the subject it is about. A technique names adversary behaviour, so declaring one asserts that an adversary did something; a rule that cannot attribute what it reports to anyone SHALL declare none, and a rule whose own documentation names this product's components among the likely causes cannot attribute it.

Declaring none is a complete mapping rather than a gap. A signal that a host has stopped capturing is an operational statement, and it earns its severity from the consequence rather than from an attribution: a host that is not capturing needs an operator whatever caused it. An unearned technique is not a harmless overstatement either, because it reaches the alert row an analyst reads and, for a rule that appears on the operator-facing catalog, the coverage export a customer reads.

#### Scenario: A rule advertises ATT&CK techniques

- **GIVEN** a rule that declares technique identifiers such as `T1059.002` and `T1105`
- **WHEN** the rule fires and an alert is persisted
- **THEN** the alert row carries those technique identifiers
- **AND** subsequent edits to the rule's technique mapping do not modify the historical alert's stamped list

#### Scenario: A rule that cannot attribute what it reports declares no technique

- **GIVEN** a rule reporting that the agent's own recovery of a stopped capture provider gave up
- **AND** that rule documents this product's own components among the likely causes
- **WHEN** it fires and an alert is persisted
- **THEN** the alert row carries no ATT&CK technique
- **AND** the alert keeps its severity and its text, because the host still needs an operator

