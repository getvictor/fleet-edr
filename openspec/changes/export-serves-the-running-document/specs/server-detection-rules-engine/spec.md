# Server detection rules engine

## ADDED Requirements

### Requirement: The export serves the document a rule was loaded from

When a registered rule was loaded from a rule document, the system SHALL export that document verbatim, and SHALL resolve it from the rule the deployment is RUNNING rather than by matching the rule's identifier against content embedded in the build.

The distinction is not academic. A rule's identity is its file stem rather than its path, so an operator who stores their own version of a shipped detection keeps that detection's identifier and the rule that evaluates is theirs. An identifier resolved against the build's own copy still finds the shipped document under that stem, so the export returns content the deployment is not running and the operator did not write. The export exists to answer "what is running here", and it is reached for precisely when someone doubts the answer, so returning a plausible wrong document is worse than returning nothing.

The system SHALL distinguish a rule that came from no document from one whose document is empty. A rule expressed in code was never a file, and the system SHALL render a document for it rather than exporting zero bytes.

The system SHALL NOT decide what to export by asking whether a rule is upstream's. Whether a rule carries a document and whose rule it is are separate questions with different answers for an operator's own rule content, and one predicate answering both will be wrong for whichever question it was not written for.

#### Scenario: A rule an operator overwrote exports as theirs

- **GIVEN** a deployment where an operator has stored their own rule document under the identifier of a rule the build ships
- **WHEN** they export that rule
- **THEN** they receive the document they stored, byte for byte
- **AND** they do not receive the shipped document the build still carries under that identifier

#### Scenario: A rule expressed in code is rendered

- **GIVEN** a registered detection written in code, which was never loaded from a document
- **WHEN** an operator exports it
- **THEN** a declarative rule file is rendered for it
- **AND** the response is not an empty document
