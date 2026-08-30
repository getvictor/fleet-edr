# Server detection rules engine: an alert from a converted rule names what fired delta

## ADDED Requirements

### Requirement: An alert from a converted rule names what fired

The system SHALL describe a finding from a rule whose logic is a detection block using the values that detection matched on, read back from the same fields, so that the text an operator reads cannot drift from the condition that produced it.

The system SHALL NOT include attacker-controlled content in that description where naming the matched element is sufficient. An injected library path identifies nothing the operator needs that the variable name does not, and the description is read in an alert feed, so the value is withheld while the variable is named.

Where a detection matched a list-valued field, the system SHALL name the element that satisfied it rather than the whole list, since the evaluator reports only that some element matched.

#### Scenario: A finding names the matched element rather than the whole field

- **GIVEN** a rule whose detection matched one element of a list-valued field
- **WHEN** the finding is built
- **THEN** its description names that element

#### Scenario: An attacker-supplied value is withheld from the description

- **GIVEN** a rule that fires on an environment assignment
- **WHEN** the finding is built
- **THEN** it names the variable and not the value assigned to it
