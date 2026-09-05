# Rule content: provenance delta

## ADDED Requirements

### Requirement: A rule document records where it came from

The system SHALL record, for every stored rule document, whether it was shipped with the product or written by an operator.

Provenance SHALL be recorded when the document is stored, not derived from its path or its content. A rule's identity comes from its file stem rather than its path, and operators choose their own paths, so anything derived from a path is both contradicted by that and guessable by the operator it describes. How a document arrived is a fact only the store observes.

A document written through the authoring surface SHALL be recorded as the operator's, whatever path it is stored under.

#### Scenario: A seeded document is recorded as shipped with the product

- **GIVEN** an empty corpus and a product that ships rule content
- **WHEN** the corpus is seeded
- **THEN** every seeded document is recorded as having come from the product

#### Scenario: An authored document is recorded as the operator's

- **GIVEN** an operator writes a rule document
- **WHEN** it is stored
- **THEN** it is recorded as written by an operator, whatever path they chose

#### Scenario: Replacing a shipped document with an authored one changes its provenance

- **GIVEN** a document that was shipped with the product
- **WHEN** an operator writes over it
- **THEN** it is recorded as written by an operator, because it now is

### Requirement: An unrecognised provenance is refused

The system SHALL refuse rule content whose recorded provenance it does not recognise, both when storing it and when reading it back, rather than interpreting it as either known provenance.

An unrecognised value is not "written by an operator", so attribution would credit it upstream, and it is not "shipped with the product", so the pack identity would exclude it. Treating one as shipped would state a licence claim about content the system cannot vouch for.

#### Scenario: Content declaring an unrecognised provenance is not stored

- **GIVEN** a corpus holding rule content
- **WHEN** a replacement declares a provenance the system does not recognise
- **THEN** the replacement is refused and the stored content is unchanged

#### Scenario: A stored document with an unrecognised provenance is not interpreted

- **GIVEN** a stored document whose recorded provenance the system does not recognise
- **WHEN** the corpus is read
- **THEN** the read fails rather than crediting the document to an upstream project

### Requirement: Attribution follows recorded provenance

The system SHALL credit a rule according to where its document came from.

A rule shipped with the product SHALL keep crediting the upstream project and the rule's own author, which is what the licence its content carries requires.

A rule an operator wrote SHALL NOT be credited to an upstream project, and its alerts SHALL NOT carry that project's attribution. Crediting an upstream project for an operator's own work is false, and because that credit is how the system honours the licence upstream content carries, it also misstates the licensing of work not under it.

#### Scenario: An operator's rule is not credited upstream

- **GIVEN** a rule an operator wrote
- **WHEN** its attribution is shown
- **THEN** it is not credited to an upstream project

#### Scenario: An alert from an operator's rule carries no upstream attribution

- **GIVEN** an alert raised by a rule an operator wrote
- **WHEN** the alert records its attribution
- **THEN** it does not carry an upstream project's credit

#### Scenario: A shipped rule keeps its upstream credit

- **GIVEN** a rule shipped with the product
- **WHEN** its attribution is shown
- **THEN** it credits the upstream project and the rule's own author, as before

### Requirement: The corpus identifies which shipped pack it holds

The system SHALL identify the pack of shipped rule content a corpus holds, in a way that changes exactly when that content changes and requires no separate version to be maintained by hand.

The identity SHALL be derived from the shipped content itself, so that a deployment can determine whether it is running the pack in the build it is executing by comparing rather than by trusting a recorded label.

#### Scenario: The identity changes when the shipped content changes

- **GIVEN** two sets of shipped rule content that differ
- **WHEN** each is identified
- **THEN** the identities differ

#### Scenario: The identity is stable for unchanged content

- **GIVEN** the same shipped rule content
- **WHEN** it is identified more than once
- **THEN** the identity is the same each time

#### Scenario: Content written by an operator does not change the pack identity

- **GIVEN** a corpus holding shipped content
- **WHEN** an operator adds a rule of their own
- **THEN** the pack identity is unchanged, because the shipped content is unchanged

#### Scenario: Changing a shipped rule changes the pack identity

- **GIVEN** a corpus holding shipped content
- **WHEN** an operator writes their own version of one of those rules, or deletes one
- **THEN** the pack identity changes, because the corpus no longer holds the shipped content it did
