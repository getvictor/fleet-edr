# Detection rules engine

## ADDED Requirements

### Requirement: The vendored upstream corpus is registered and does not alert until promoted

The system SHALL register the upstream detection rules it vendors alongside the rules it authors, so they evaluate against live events.

Each vendored rule SHALL operate in `monitor` by default, recording what it would have fired on without persisting an alert, until an operator promotes it. The system did not author these rules and cannot vouch for their behaviour on a given fleet; a catalog that raises alerts an operator has no basis to trust loses the alerts that were right along with the ones that were not.

Every operator-facing surface that describes the catalog SHALL distinguish a rule that does not alert from one that does. In particular, a coverage export SHALL NOT represent a technique covered only by non-alerting rules the same way it represents one covered by an alerting rule, because such a document is read as a claim about what the product raises.

A vendored rule SHALL be attributed. Its upstream project and the rule's own author SHALL be reported wherever the catalog is described to an operator, because a vendored rule is otherwise presented exactly as one this project wrote and a reader cannot tell them apart. A rule this project authored SHALL report no attribution rather than naming this project, so the field distinguishes rather than decorates.

A vendored rule's declarative form SHALL be the file that was vendored. The system SHALL NOT emit a second rendering of it in its own format, and a request to export such a rule SHALL return the vendored bytes.

Guards that enforce this project's authoring standards SHALL apply to the rules it authors. Where a vendored rule falls outside one, the exception SHALL be recorded by name, so that scoping a guard costs visibility rather than concealing the gap.

#### Scenario: The vendored corpus is registered alongside the rules this project authored

- **GIVEN** a vendored upstream corpus whose rules this sensor can run
- **WHEN** the rule catalog is built
- **THEN** every runnable vendored rule is registered, and the rules this project authored are registered as well

#### Scenario: A vendored rule raises no alert until an operator promotes it

- **GIVEN** a registered vendored rule and no operator setting for it
- **WHEN** an event it matches is evaluated
- **THEN** no alert is persisted and the match is recorded as an observability signal

#### Scenario: Coverage from non-alerting rules is not claimed as coverage

- **GIVEN** one technique covered only by rules that do not alert, and another covered by a rule that does
- **WHEN** the ATT&CK coverage layer is built
- **THEN** the two are given different scores, and the first is annotated as raising no alert until promoted

#### Scenario: A vendored rule is attributed on the operator-facing catalog

- **GIVEN** a registered vendored rule and a registered rule this project authored
- **WHEN** an operator reads the rule catalog surface
- **THEN** the vendored rule's entry names its upstream project and that rule's author
- **AND** the authored rule's entry names no source

#### Scenario: Exporting a vendored rule returns the upstream file

- **GIVEN** a registered vendored rule
- **WHEN** an operator exports it
- **THEN** the response is the vendored file's bytes rather than a rendering of the rule in this project's format

#### Scenario: A vendored rule outside an authoring standard is recorded by name

- **GIVEN** a vendored rule that claims no ATT&CK technique, or whose title does not meet this project's naming standard
- **WHEN** the catalog guards run
- **THEN** the rule is named in the recorded set of exceptions, and a change to that set fails the guard
