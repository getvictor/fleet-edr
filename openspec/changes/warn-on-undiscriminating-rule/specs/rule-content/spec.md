# Rule content: undiscriminating-rule warning delta

## ADDED Requirements

### Requirement: A rule that discriminates nothing is warned about

The system SHALL warn when submitted rule content defines a search that every event carrying its fields satisfies, and SHALL store the content.

Warning rather than refusing is deliberate. An operator writing a deliberately broad hunting rule is doing something legitimate, and refusing it would substitute the system's judgement for theirs on a question the system cannot answer, which is whether they meant it.

The warning SHALL name the searches responsible, because an operator fixing it needs to know which part of their rule to look at.

The system SHALL NOT warn about a pattern that restricts the value in any way, including one that requires at least one character and one that requires the value to be empty. A warning that fires on rules an operator wrote deliberately is ignored, and then reports nothing when it matters.

The system SHALL NOT claim to decide this for a regular-expression pattern. Whether a regular expression matches every value is a question about a different matcher, and answering it wrongly in the reassuring direction would be worse than not answering.

#### Scenario: A search matching every value is warned about

- **GIVEN** a submitted rule whose search matches any value of its field
- **WHEN** it is validated
- **THEN** it is accepted, and the warning names that search

#### Scenario: A discriminating rule is not warned about

- **GIVEN** a submitted rule whose searches all restrict the values they match
- **WHEN** it is validated
- **THEN** it is accepted with no such warning

#### Scenario: A pattern requiring at least one character is not warned about

- **GIVEN** a submitted rule whose pattern requires the value to be non-empty
- **WHEN** it is validated
- **THEN** it is accepted with no such warning, because it restricts what matches

#### Scenario: A pattern requiring an empty value is not warned about

- **GIVEN** a submitted rule whose pattern matches only an empty value
- **WHEN** it is validated
- **THEN** it is accepted with no such warning, because it is the narrowest pattern rather than the broadest
