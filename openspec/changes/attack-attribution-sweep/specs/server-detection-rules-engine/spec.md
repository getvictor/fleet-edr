# Server detection rules engine: every technique names something observed

## MODIFIED Requirements

### Requirement: MITRE ATT&CK technique stamping

The system SHALL stamp each persisted alert with MITRE ATT&CK technique identifiers, taken from the finding first and the rule second. A finding that states a list of its own is stamped with that list, which is how a rule covering several techniques claims only the ones that applied to the finding at hand rather than its whole union. A finding that states none inherits the list its rule declares. A technique carried by a conditional escalation that applied is added to whichever of those was used, and a technique already present is not repeated.

The stamped list MUST be preserved on the alert row even if the rule's technique mapping is later refined.

A rule SHALL declare a technique only for something it OBSERVED, not for the subject it is about.

What counts as observing it depends on what the technique NAMES, and the two cases are different obligations. A technique that names a BEHAVIOUR is observed when the behaviour is: a Unix shell ran whether an administrator or an intruder started it, so a rule that matches the shell has seen the technique and does not owe an account of intent. A technique that names an ACTOR'S ACTION is observed only when something about the actor is: impairing defenses is somebody doing something, and a rule that sees only the resulting state has not seen it, however reliably that state follows from the action.

A rule that cannot observe what its technique names SHALL declare none.

Separating a known benign explanation from what a rule reports is what makes the rule's signal sound, and it is a different question from which technique the rule may declare. A rule that names a product-caused false positive and then discriminates against it still has to meet the test above for whatever it declares: the separation earns the alert, not the attribution. And a rule whose own documentation names this product's components among the likely causes of the very thing it reports has separated nothing. It is describing a state with several possible causes, one of them ours, which is neither an observed behaviour nor an observed actor.

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
