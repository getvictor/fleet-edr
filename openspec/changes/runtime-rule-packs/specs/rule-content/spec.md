# Rule content

## ADDED Requirements

### Requirement: Rule content is stored, and is the source the catalog loads from

The system SHALL store rule content durably, separately from the binary, and SHALL build its evaluatable rule set from that store rather than from content compiled in. Rule content SHALL be owned by a context distinct from the one that evaluates rules, which produces definitions and consumes nothing from the evaluator (ADR-0021).

Storing the content is what allows a detection to ship without a release, which is the whole purpose. It is also what makes rule content an aggregate rather than a projection of the catalog, and therefore what makes the separate ownership a boundary rather than a directory.

The stored content SHALL carry a version that changes whenever the content changes, and that version SHALL be readable without reading the content. A replica converges by noticing change, and noticing must be cheap enough to do on an interval where re-reading every document is not.

Replacing the stored content SHALL be atomic and SHALL replace it whole. Content is valid or invalid as a set: a rule removed from the source has to disappear rather than linger, and no reader may observe part of one version alongside part of another. The version SHALL advance in the same transaction, so a reader that sees a new version can only read the content that belongs to it.

The stored content SHALL be read back byte-identically, under the same identity the loader reads it by, so that storing content cannot change which detections run. That identity SHALL be the document's path, because rule identity is derived from it and collisions are detected by it before anything is parsed.

#### Scenario: The catalog loads the stored content

- **GIVEN** rule content in the store
- **WHEN** the rule set is built
- **THEN** it is built from the stored content
- **AND** the rules it yields are the same, and in the same order, as loading that content from the binary would give

#### Scenario: Replacing content removes what is no longer in it

- **GIVEN** stored content holding a rule that the replacement does not
- **WHEN** the content is replaced
- **THEN** that rule is no longer in the store
- **AND** the version has advanced

#### Scenario: The version is readable without reading the content

- **GIVEN** stored content
- **WHEN** a replica checks for change
- **THEN** it can read the version alone

### Requirement: An unavailable or unusable store leaves detections running

The system SHALL continue evaluating detections when the stored content cannot be used. Where no previous good content is held, it SHALL fall back to the content compiled into the build, which is the same content the store would have been seeded with.

A deployment whose store is empty, unreachable, or holding content that fails to load SHALL therefore behave as it did before rule content was stored. The alternative is a server that starts with no detections because of a storage problem, which trades a bounded loss of the ability to change rules for an unbounded loss of the rules themselves.

Falling back for a REASON SHALL be reported. An empty store SHALL NOT be reported as a problem, because it is the expected state of a deployment that has not been seeded yet.

#### Scenario: Content that fails to load does not stop detection

- **GIVEN** stored content that cannot be loaded
- **WHEN** the rule set is built
- **THEN** the rules compiled into the build are evaluated instead
- **AND** the reason is reported

#### Scenario: An unseeded store is not an error

- **GIVEN** a store holding no content
- **WHEN** the rule set is built
- **THEN** the rules compiled into the build are evaluated
- **AND** nothing is reported as wrong

### Requirement: Seeding never overwrites content that is already there

The system SHALL seed the store from the content compiled into the build only when the store holds no content. It SHALL NOT seed based on a comparison between the build's content and the stored content.

The distinction is what keeps authored content safe. Content in the store can be edited, so a seed that ran whenever the build looked newer would replace an operator's rules with the vendored set on the next restart. An empty store is the only state in which seeding is certainly not destroying something.

Seeding SHALL be safe to attempt on every start and on every replica, and a failure to seed SHALL NOT prevent the system from starting.

#### Scenario: An empty store is seeded

- **GIVEN** a store holding no content
- **WHEN** the system starts
- **THEN** the store holds the content compiled into the build

#### Scenario: A store holding content is left alone

- **GIVEN** a store holding content that differs from the build's
- **WHEN** the system starts again
- **THEN** the stored content is unchanged
