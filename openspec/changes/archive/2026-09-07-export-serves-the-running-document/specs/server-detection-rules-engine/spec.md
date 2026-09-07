# Server detection rules engine

## ADDED Requirements

### Requirement: The export serves the document a rule was loaded from

When a registered rule was loaded from a rule document, the system SHALL export that document verbatim, and SHALL resolve it from the rule set the deployment currently has in force rather than by matching the rule's identifier against content embedded in the build.

The set in force means the one the rule catalog reports, which during a content reload is briefly ahead of the one detection is evaluating: installing a new set replaces the catalog's copy before rebuilding what evaluation derives from it, and evaluations already running finish on the generation they started with. The export SHALL follow the catalog, so that a rule read alongside the catalog agrees with it, and that bounded divergence is accepted rather than closed, since closing it would require serialising the per-batch evaluation path against a write that happens only when content changes.

The distinction is not academic. A rule's identity is its file stem rather than its path, so an operator who stores their own version of a shipped detection keeps that detection's identifier and the rule that evaluates is theirs. An identifier resolved against the build's own copy still finds the shipped document under that stem, so the export returns content the deployment is not running and the operator did not write. The export exists to answer "what is running here", and it is reached for precisely when someone doubts the answer, so returning a plausible wrong document is worse than returning nothing.

The system SHALL distinguish a rule that came from no document from one whose document is empty. A rule expressed in code was never a file, and the system SHALL render a document for it rather than exporting zero bytes.

The rule and the metadata describing it SHALL be resolved from ONE generation of the active rule set. The two are read together on every export, the set is replaced wholesale when rule content reloads, and a reload landing between two separate reads leaves the system describing a rule the deployment is no longer running. That is not a cosmetic inconsistency: for a rule loaded from a document, its metadata alone renders to nothing, so the export fails rather than reporting a stale answer.

Exporting a document an OPERATOR wrote SHALL require the authorization that reading rule content requires, and exporting one that shipped with the product SHALL NOT. Until the export served the running document it could only return the product's own content, so the authorization that reads the rule catalog was the whole gate; the same gate over an operator's own rule hands it to roles that are refused it on the surface built for rule content. Requiring the stricter authorization for every rule would instead withdraw export of the shipped rules from roles that already read them on the catalog.

The system SHALL NOT decide what to export by asking whether a rule is upstream's. Whether a rule carries a document and whose rule it is are separate questions with different answers for an operator's own rule content, and one predicate answering both will be wrong for whichever question it was not written for.

#### Scenario: A rule an operator overwrote exports as theirs

- **GIVEN** a deployment where an operator has stored their own rule document under the identifier of a rule the build ships
- **WHEN** they export that rule
- **THEN** they receive the document they stored, byte for byte
- **AND** they do not receive the shipped document the build still carries under that identifier

#### Scenario: Exporting an authored rule needs more access

- **GIVEN** a reader authorized to read the rule catalog but not to read rule content
- **WHEN** they export a rule an operator wrote on that deployment
- **THEN** the request is refused
- **AND** exporting a rule that shipped with the product still succeeds for them

#### Scenario: A rule expressed in code is rendered

- **GIVEN** a registered detection written in code, which was never loaded from a document
- **WHEN** an operator exports it
- **THEN** a declarative rule file is rendered for it
- **AND** the response is not an empty document
