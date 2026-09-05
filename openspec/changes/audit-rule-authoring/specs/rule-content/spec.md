# Rule content: operator authoring surface delta

## ADDED Requirements

### Requirement: Operators reach authoring through a governed surface

The system SHALL expose rule-content authoring to operators, and SHALL authorize every request to it through the same chokepoint every other privileged action passes.

Reading the corpus and changing it SHALL be separately authorized, so an operator may be permitted to see what the deployment detects without being permitted to change it.

An unauthorized request SHALL be refused without disclosing whether the document it named exists, because existence is itself information about what a deployment detects.

#### Scenario: An operator without write permission cannot change rule content

- **GIVEN** an operator authorized to read rule content but not to change it
- **WHEN** they submit a change
- **THEN** it is refused and the corpus is unchanged

#### Scenario: An operator without read permission cannot see rule content

- **GIVEN** an operator authorized for neither
- **WHEN** they request the corpus
- **THEN** it is refused

#### Scenario: A refusal does not disclose whether the document exists

- **GIVEN** an operator not authorized to change rule content
- **WHEN** they submit a change naming a document that does not exist
- **THEN** the refusal is the same as for a document that does exist

### Requirement: Every authoring change is attributable

The system SHALL record an audit entry for every rule-content change that took effect, attributing it to the acting principal, naming the document, and distinguishing a write from a deletion.

A submission that was refused SHALL NOT be recorded as a mutation. It did not change the corpus, and recording it as though it had would make the audit trail disagree with the thing it audits. This does not make refusals invisible: an authorization denial is already recorded by the chokepoint, and a validation refusal is returned to the operator with its reason.

An operator SHALL state a reason for a change, and it SHALL be recorded, so the trail says why as well as who and what.

#### Scenario: A write is attributed

- **GIVEN** an operator writes a rule document
- **WHEN** the write takes effect
- **THEN** an audit entry attributes it to that operator, names the document, and records their stated reason

#### Scenario: A deletion is attributed

- **GIVEN** an operator deletes a rule document
- **WHEN** the deletion takes effect
- **THEN** an audit entry attributes it to that operator and names the document

#### Scenario: A refused submission is not recorded as a mutation

- **GIVEN** a submission the validator refuses
- **WHEN** it is refused
- **THEN** no mutation audit entry is recorded

#### Scenario: A change without a stated reason is refused

- **GIVEN** an operator submits a change with no reason
- **WHEN** it is received
- **THEN** it is refused and the corpus is unchanged

### Requirement: Operators can check content before publishing it

The system SHALL let an operator validate a proposed change without applying it, reporting what would be refused and what would be warned about.

A check SHALL NOT change the corpus and SHALL NOT be recorded as a mutation, because nothing happened to the thing being audited.

#### Scenario: A check reports refusal without changing anything

- **GIVEN** a proposed change the validator would refuse
- **WHEN** an operator checks it rather than submitting it
- **THEN** the reason is reported, the corpus is unchanged, and no mutation is recorded

#### Scenario: A check reports warnings for content that would be accepted

- **GIVEN** a proposed change that would be accepted with warnings
- **WHEN** an operator checks it
- **THEN** the warnings are reported and the corpus is unchanged
