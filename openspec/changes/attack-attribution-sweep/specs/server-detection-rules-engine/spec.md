# Server detection rules engine: every technique names something observed

## MODIFIED Requirements

### Requirement: MITRE ATT&CK technique stamping

The system SHALL stamp each persisted alert with MITRE ATT&CK technique identifiers, taken from the finding first and the rule second. A finding that states a list of its own is stamped with that list, which is how a rule covering several techniques claims only the ones that applied to the finding at hand rather than its whole union. A finding that states none inherits the list its rule declares. A technique carried by a conditional escalation that applied is added to whichever of those was used, and a technique already present is not repeated.

The stamped list MUST be preserved on the alert row even if the rule's technique mapping is later refined.

A rule SHALL declare a technique only for something it OBSERVED, not for the subject it is about. A technique names adversary behaviour, so declaring one asserts that an adversary did something, and a rule that cannot attribute what it reports to anyone SHALL declare none.

Naming this product's own components in a rule's documentation is not by itself that condition, and telling the two apart is the whole test. A rule that names a product-caused explanation as a known false positive and then SEPARATES it from the behaviour it reports still attributes what it does report, because that separation is itself the observation. A rule whose documentation names this product's components among the likely causes of the very thing it reports, and which offers nothing that tells those causes apart from an adversary, is the rule this excludes.

Declaring none is a complete mapping rather than a gap. A signal that a host has stopped capturing is an operational statement, and it earns its severity from the consequence rather than from an attribution: a host that is not capturing needs an operator whatever caused it. An unearned technique is not a harmless overstatement either, because it reaches the alert row an analyst reads and, for a rule that appears on the operator-facing catalog, the coverage export a customer reads.

A rule that declares no technique SHALL NOT itself write one into its alert text either. The text is carried onto the alert verbatim and read by the same analyst, so an attribution the rule puts in prose is the same claim by another route, and removing it from the structured mapping alone leaves the claim standing where it is actually read. Text an operator supplied is theirs to write and is out of scope: a rule that passes it through is not the one making the claim.

Where a rule matches something specific enough to identify a sub-technique, it SHALL declare the sub-technique rather than its parent, and SHALL NOT declare both. A rule that matches a shell by path knows which interpreter ran, so the parent understates a claim that is actually precise, and a coverage export renders a parent hit differently from a sub-technique one. Declaring both is the same overstatement twice.

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

#### Scenario: A rule declares the sub-technique it can identify

- **GIVEN** a rule whose match identifies a sub-technique, such as one matching a Unix shell by path
- **WHEN** its ATT&CK mapping is read
- **THEN** it names that sub-technique
- **AND** it does not also name the parent technique
