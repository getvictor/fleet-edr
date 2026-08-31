# Server detection rules engine: an upstream Sigma rule runs here unmodified delta

## ADDED Requirements

### Requirement: A detection can be an upstream Sigma file with nothing added

The system SHALL load a rule from a Sigma file that carries no engine-specific keys, deriving what it needs from what Sigma already defines: the rule's identifier from the file name, its target platforms from the log source product, the event types it consumes from the log source category, its severity from its level, and its technique mapping from its tags.

Requiring any additional key would fork the upstream corpus, because a file that must be edited cannot be re-synced without a conflict and its provenance can no longer be checked against upstream.

Operator tuning of an imported rule SHALL live outside the rule file, so that re-syncing the file does not discard it.

#### Scenario: An unmodified upstream rule loads and fires

- **GIVEN** a Sigma rule file taken unchanged from an upstream corpus
- **WHEN** it is imported and an event it describes is evaluated
- **THEN** the rule produces a finding carrying the severity its level maps to

### Requirement: A rule this sensor cannot run is refused by name

The system SHALL refuse to import a rule whose fields or category it cannot map, and SHALL report which field or category was the reason. Importing it anyway would install a detection that can never match, which is indistinguishable from the behaviour never occurring.

Refusing one rule SHALL NOT refuse the rest. An upstream corpus is written for many sensors, so some of its rules will always read data this one does not collect, and abandoning the import over them would import nothing.

A file that cannot be read or parsed, or that claims an identifier another file already claimed, SHALL fail the import rather than being reported as a rejection: those mean the import itself is broken rather than that one detection does not fit.

#### Scenario: A rule reading an unavailable field is refused, and the others still import

- **GIVEN** a corpus in which one rule reads a field this sensor does not collect
- **WHEN** the corpus is imported
- **THEN** that rule is reported as refused, naming the field, and every other rule imports

#### Scenario: Two files claiming one identifier fail the import

- **GIVEN** two rule files that resolve to the same identifier
- **WHEN** the corpus is imported
- **THEN** the import fails, rather than one file silently replacing the other
