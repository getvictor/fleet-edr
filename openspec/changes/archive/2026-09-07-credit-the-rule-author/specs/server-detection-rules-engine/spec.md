# Detection rules engine

## ADDED Requirements

### Requirement: An alert credits the author of the rule that raised it

Every registered detection SHALL name an origin. A detection that declares no upstream SHALL be credited to this project; a detection that declares an upstream but names no author SHALL be credited to neither, since claiming such a rule as this project's work would credit the wrong party. Attribution is therefore total, and a surface displaying it need not decide what to render when it is absent.

An alert SHALL record the attribution of the detection that raised it, as of the moment it was raised. The system SHALL derive that attribution from the detection rather than from the finding, so that a detection cannot forge, reassign, or suppress its own credit.

Recorded attribution SHALL NOT change when the detection it names is later re-credited, removed, or replaced. Resolving attribution from the catalog when an alert is displayed would leave an alert whose detection has since left the catalog displaying no credit at all, which is the outcome the requirement exists to prevent.

Every surface that displays an alert SHALL display its attribution, as rendered text rather than as a hover affordance. A credit revealed only on hover is not available to a reader scanning a list, printing it, or using an assistive technology that does not announce it.

An alert that records no attribution SHALL be displayed without a credit rather than with an invented one. Alerts raised before attribution was recorded carry none, and substituting a default would assert something the alert does not record.

#### Scenario: An alert from a vendored rule credits its author

- **GIVEN** a registered vendored detection that names an upstream project and author
- **WHEN** it raises an alert and an operator views that alert
- **THEN** the alert displays the upstream project and that rule's author

#### Scenario: An alert from a rule this project wrote credits this project

- **GIVEN** a registered detection that declares no upstream
- **WHEN** it raises an alert and an operator views that alert
- **THEN** the alert displays this project as the rule's author

#### Scenario: A rule declaring an upstream but naming no author is not claimed as ours

- **GIVEN** a registered detection that declares an upstream source and names no author
- **WHEN** its attribution is resolved
- **THEN** the attribution names neither this project nor an author

#### Scenario: Attribution recorded on an alert survives the rule being re-credited

- **GIVEN** an alert raised by a detection crediting one author
- **WHEN** that detection is subsequently re-credited to a different author
- **THEN** the existing alert still displays the author it was raised with

#### Scenario: An alert recording no attribution displays no credit

- **GIVEN** an alert that records no attribution
- **WHEN** an operator views it
- **THEN** no credit is displayed for it

### Requirement: A detection's references are available beside its attribution

A detection SHALL carry the sources it was written from, and the operator-facing catalog SHALL report them. A vendored detection's references are the upstream rule's own, so that a credit can be checked against the work it credits rather than being taken on trust.

A reference SHALL be presented as a followable link only when it is an `http` or `https` URL. References on a vendored detection are third-party content, and presenting an arbitrary scheme as a link makes a citation into a means of execution. A reference that is not such a URL SHALL still be displayed, without being followable.

#### Scenario: An upstream reference is offered as a link

- **GIVEN** a registered vendored detection citing an `https` URL
- **WHEN** an operator reads that detection's documentation
- **THEN** the citation is displayed and is followable

#### Scenario: A reference carrying an executable scheme is displayed but not followable

- **GIVEN** a registered detection whose citation uses a scheme other than `http` or `https`
- **WHEN** an operator reads that detection's documentation
- **THEN** the citation is displayed and is not followable

## MODIFIED Requirements

### Requirement: The vendored upstream corpus is registered and does not alert until promoted

The system SHALL register the upstream detection rules it vendors alongside the rules it authors, so they evaluate against live events.

Each vendored rule SHALL operate in `monitor` by default, recording what it would have fired on without persisting an alert, until an operator promotes it. The system did not author these rules and cannot vouch for their behaviour on a given fleet; a catalog that raises alerts an operator has no basis to trust loses the alerts that were right along with the ones that were not.

Every operator-facing surface that describes the catalog SHALL distinguish a rule that does not alert from one that does. In particular, a coverage export SHALL NOT represent a technique covered only by non-alerting rules the same way it represents one covered by an alerting rule, because such a document is read as a claim about what the product raises.

A vendored rule SHALL be attributed. Its upstream project and the rule's own author SHALL be reported wherever the catalog is described to an operator, because a vendored rule is otherwise presented exactly as one this project wrote and a reader cannot tell them apart. A rule this project authored SHALL report this project as its attribution rather than reporting none: attribution now also rides the alert view, where an absent credit cannot be distinguished from a credit that failed to arrive, and the two populations remain distinguishable by the value.

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
- **AND** the authored rule's entry names this project

#### Scenario: Exporting a vendored rule returns the upstream file

- **GIVEN** a registered vendored rule
- **WHEN** an operator exports it
- **THEN** the response is the vendored file's bytes rather than a rendering of the rule in this project's format

#### Scenario: A vendored rule outside an authoring standard is recorded by name

- **GIVEN** a vendored rule that claims no ATT&CK technique, or whose title does not meet this project's naming standard
- **WHEN** the catalog guards run
- **THEN** the rule is named in the recorded set of exceptions, and a change to that set fails the guard
