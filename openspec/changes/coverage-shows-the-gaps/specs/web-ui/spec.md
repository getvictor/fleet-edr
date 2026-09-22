## ADDED Requirements

### Requirement: Coverage reports what is not covered

The coverage view SHALL report the techniques no rule covers, not only the ones some rule does. A view built from the covered set alone can state a count and not a fraction: a reader learns how many techniques are covered and cannot learn how many there were to cover, which is the number that says whether the deployment is well covered or barely started.

A technique SHALL be counted as in scope only when ATT&CK records it for the platform the product watches. The enterprise matrix is mostly techniques that cannot be run against this estate, and counting them as missing would bury the ones that can under them. A technique ATT&CK records no platform for SHALL be treated as in scope, because an absent list is a fact about the published bundle rather than evidence the technique does not apply, and dropping it would hide a gap on the strength of missing data.

The uncovered techniques SHALL be listed, grouped the same way the covered ones are, so the two are read as two halves of one matrix rather than as two different pages.

An uncovered technique SHALL offer to be answered: an operator authorized to write rules SHALL be offered a way to open the authoring surface with that technique already named, so closing the gap does not depend on them carrying the identifier there themselves. An operator not so authorized SHALL still be shown the gap, which is the part they can act on by asking someone who is.

Where a technique identifier is carried to the authoring surface, it SHALL be accepted only in ATT&CK's own form. It arrives as a request parameter, which anything can write, and it is placed into a document the rule loader parses.

#### Scenario: The view states how much is not covered

- **GIVEN** a deployment whose rules cover some of the techniques in scope
- **WHEN** an operator reads the coverage view
- **THEN** it reports how many in-scope techniques no rule covers
- **AND** how many techniques are in scope

#### Scenario: Techniques off the platform are not counted as gaps

- **GIVEN** a technique ATT&CK does not record for the platform the product watches
- **WHEN** the uncovered techniques are counted and listed
- **THEN** that technique is neither counted nor listed

#### Scenario: A gap offers the rule that would close it

- **GIVEN** an operator authorized to write rules, reading an uncovered technique
- **WHEN** they follow the offer to write one
- **THEN** the authoring surface opens with that technique already named in the document

#### Scenario: A gap is shown to an operator who cannot write rules

- **GIVEN** an operator not authorized to write rules
- **WHEN** they read the uncovered techniques
- **THEN** the techniques are listed
- **AND** no offer to write a rule is made

#### Scenario: A technique identifier that is not one is refused

- **GIVEN** a request to the authoring surface carrying a technique identifier that is not in ATT&CK's form
- **WHEN** the starting document is prepared
- **THEN** the identifier is not placed into it
