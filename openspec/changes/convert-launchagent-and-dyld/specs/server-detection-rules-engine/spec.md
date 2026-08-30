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

### Requirement: Converting a rule may narrow what it detects, never widen it

The system SHALL NOT begin alerting on anything a rule did not alert on before its logic moved into its file. Where reading a computed field corrects a matcher's behaviour, the correction SHALL remove findings rather than add them, and SHALL be recorded rather than absorbed silently.

A conversion is offered as behaviour-preserving, so an operator has no reason to re-tune a rule afterwards. A widening breaks that promise in the direction that costs an analyst time; a narrowing that is documented does not.

#### Scenario: A conversion removes a finding rather than adding one

- **GIVEN** a rule whose converted form declines an invocation its previous implementation matched
- **WHEN** the two are compared over generated invocations
- **THEN** every difference is the converted form declining, and none is it firing where the previous implementation did not
