# Server detection rules engine: a technique is a claim about what was observed

## MODIFIED Requirements

### Requirement: MITRE ATT&CK technique stamping

The system SHALL stamp each persisted alert with the MITRE ATT&CK technique identifiers declared by the firing rule. The stamped list MUST be preserved on the alert row even if the rule's technique mapping is later refined.

A rule SHALL declare a technique only for something it OBSERVED, not for the subject it is about. A technique names adversary behaviour, so declaring one asserts that an adversary did something, and a rule that cannot attribute what it reports to anyone SHALL declare none.

Naming this product's own components in a rule's documentation is NOT by itself that condition, and the distinction is the whole test. A rule that names a product-caused explanation as a known false positive AND separates it from the behaviour it reports still attributes what it does report: the separation is the observation. A rule that names this product's components among the likely causes of the very thing it reports, and offers nothing that tells those causes apart from an adversary, does not, and SHALL declare no technique.

Declaring none is a complete mapping rather than a gap. A signal that a host has stopped capturing is an operational statement, and it earns its severity from the consequence rather than from an attribution: a host that is not capturing needs an operator whatever caused it. An unearned technique is not a harmless overstatement either, because it reaches the alert row an analyst reads and, for a rule that appears on the operator-facing catalog, the coverage export a customer reads.

A rule that declares no technique SHALL NOT name one in its alert text either. The text is carried onto the alert verbatim and read by the same analyst, so an attribution in prose is the same claim by another route, and removing it from the structured mapping alone leaves the claim standing where it is actually read.

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
- **AND** its text names none either
- **AND** the alert keeps its severity and its operational explanation, because the host still needs an operator

