# Rule content: install the build's pack delta

## ADDED Requirements

### Requirement: The shipped rule content in a build is installed over the stored shipped content

The system SHALL install the shipped rule content carried by the running build over the shipped rule content the corpus holds, so that a deployment upgraded to obtain new detections actually runs them.

Seeding SHALL remain guarded on an empty corpus, and this SHALL be a separate operation, because relaxing that guard would overwrite an operator's own rules on every restart.

Installing SHALL replace only the shipped content. Content an operator wrote SHALL survive, including content written at a path the pack also ships, because taking that path back would discard the rule they wrote and credit its replacement to a project that did not write it.

An operator's per-rule tuning SHALL survive installing a pack.

Installing SHALL be idempotent: installing the content a corpus already holds SHALL change nothing, and SHALL NOT advance the corpus version.

A pack whose content declares itself to be an operator's SHALL be refused, because shipped content is what a pack is.

A build carrying no shipped rule content SHALL leave the stored content alone rather than removing it.

#### Scenario: A newer pack replaces the shipped content

- **GIVEN** a corpus holding shipped rule content
- **WHEN** a build carrying different shipped content is started
- **THEN** the stored shipped content is replaced by the build's, including content the newer pack adds, and content the newer pack no longer carries is removed

#### Scenario: An operator's own rule survives

- **GIVEN** a corpus holding shipped content and a rule the operator wrote
- **WHEN** a build carrying different shipped content is started
- **THEN** the operator's rule is still stored, still recorded as theirs, and still carries the content they wrote

#### Scenario: A path the operator has taken over stays theirs

- **GIVEN** an operator has written their own version of a rule that shipped, at the path it shipped under
- **WHEN** a build that still ships that path is started
- **THEN** the stored document is still the operator's, with the content they wrote

#### Scenario: An operator's tuning survives

- **GIVEN** a rule whose mode and severity an operator has set
- **WHEN** the shipped content is replaced by a newer pack carrying that rule
- **THEN** the mode and severity the operator set still apply

#### Scenario: Installing the same content again changes nothing

- **GIVEN** a corpus already holding the shipped content this build carries
- **WHEN** the build is started again
- **THEN** nothing is written and the corpus version is unchanged

#### Scenario: Installing is unaffected by an operator's override

- **GIVEN** a corpus holding this build's shipped content, with one of those rules overridden by the operator
- **WHEN** the build is started again
- **THEN** nothing is written and the corpus version is unchanged

#### Scenario: A pack declaring authored content is refused

- **GIVEN** shipped content in which a document declares itself to be an operator's
- **WHEN** it is installed
- **THEN** it is refused and the stored content is unchanged

#### Scenario: A build carrying no shipped content leaves the corpus alone

- **GIVEN** a corpus holding shipped content
- **WHEN** a build carrying no shipped rule content is started
- **THEN** the stored content is unchanged
