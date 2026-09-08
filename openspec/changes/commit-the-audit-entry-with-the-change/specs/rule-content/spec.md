# rule-content

## MODIFIED Requirements

### Requirement: Every authoring change is attributable

The system SHALL record an audit entry for every rule-content change that took effect, attributing it to the acting principal, naming the document, and distinguishing a write from a deletion.

A submission that was refused SHALL NOT be recorded as a mutation. It did not change the corpus, and recording it as though it had would make the audit trail disagree with the thing it audits. This does not make refusals invisible: an authorization denial is already recorded by the chokepoint, and a validation refusal is returned to the operator with its reason.

An operator SHALL state a reason for a change, and it SHALL be recorded, so the trail says why as well as who and what.

The entry SHALL be committed in the same transaction as the change it records, so a reader can never find one without the other. Recording it afterwards leaves a window in which a fleet's detections have changed durably and nothing names who did it or why, and the failure has no good answer at that point: returning it reports failure for a change that already happened, and swallowing it leaves the gap. Committing the two together removes the choice.

Where the audit store cannot join that transaction, because it belongs to another bounded context, the entry SHALL be committed alongside the change as an opaque record and delivered to the audit store afterwards. Delivery MAY therefore lag the change, and SHALL be retried until it succeeds; it SHALL NOT be dropped. The record's content SHALL be opaque to the context that stores it, so storing an audit entry does not require that context to know what one is.

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

#### Scenario: The audit entry commits with the change

- **GIVEN** an operator changes rule content
- **WHEN** the change commits
- **THEN** its audit entry has committed with it, in the same transaction

#### Scenario: A refused change leaves no audit entry

- **GIVEN** an operator's change is refused
- **WHEN** the refusal is returned
- **THEN** no audit entry claims the change happened, and the corpus is unchanged

#### Scenario: A delivery failure delays the audit row rather than losing it

- **GIVEN** an audit entry committed with its change
- **WHEN** delivering it to the audit store fails
- **THEN** the entry is retained and delivered by a later attempt

