# Rule content: reach the rule pack delta

## ADDED Requirements

### Requirement: An operator can see and restore the shipped rule content

The system SHALL let an authorized operator read which generation of shipped rule content a deployment runs, which generation the running build carries, and which rules differ between them, and SHALL report whether a previous generation is available to restore rather than requiring that be inferred.

The system SHALL let an authorized operator restore the previous generation. That change SHALL require a stated reason and SHALL be recorded against whoever made it, under an action of its own rather than one describing a change to a single document, because it replaces every shipped rule at once.

A restore that is refused SHALL NOT be recorded, because nothing changed.

Shipped rules not restored because the operator has taken that rule over SHALL be reported to the caller and recorded, so that content the deployment is deliberately not running is visible rather than absent without explanation.

Reading SHALL be authorized as a read and restoring as a change to rule content, matching the surface that serves the individual documents.

#### Scenario: An operator reads which shipped rules are installed

- **GIVEN** an authorized operator
- **WHEN** they read the pack status
- **THEN** it reports the installed and available generations, whether the deployment is current, whether a previous generation can be restored, and the rules added, removed and changed

#### Scenario: A restore without a reason is refused

- **GIVEN** an authorized operator
- **WHEN** they ask to restore the previous generation without stating a reason
- **THEN** the request is refused and nothing is restored

#### Scenario: A restore with nothing retained is refused as a conflict

- **GIVEN** a deployment that has never had a newer generation installed
- **WHEN** an operator asks to restore the previous generation
- **THEN** they are told there is nothing to restore, and it is not reported as a server fault

#### Scenario: A refused restore is not recorded

- **GIVEN** a restore that was refused
- **WHEN** the audit log is read
- **THEN** no restore was recorded, because the stored content is unchanged

#### Scenario: A restore reports what it withheld

- **GIVEN** a deployment where the operator has taken over one of the rules in the retained generation
- **WHEN** they restore that generation
- **THEN** the response names the shipped rule that was not restored
