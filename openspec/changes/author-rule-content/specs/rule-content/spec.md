# Rule content: operator authoring delta

## ADDED Requirements

### Requirement: Operators author rule content

The system SHALL let an authorised operator create, replace, and delete a rule document in the stored corpus.

A write SHALL make the document and the corpus version durable together, so a replica that polls the version never learns of a change it cannot then read. A write that cannot be made durable SHALL leave the corpus exactly as it was, rather than a partially applied change.

Deleting a document SHALL remove it from the corpus, so the rule it defined stops being evaluated once replicas converge. Deleting a document that is not there SHALL report that it was not there rather than reporting success, because an operator deleting a rule needs to know whether they deleted the one they meant.

#### Scenario: A created document joins the corpus

- **GIVEN** an operator submits a valid rule document under a path the corpus does not have
- **WHEN** the write succeeds
- **THEN** the document is in the corpus and the corpus version has changed

#### Scenario: A deleted document leaves the corpus

- **GIVEN** a document in the corpus
- **WHEN** an operator deletes it
- **THEN** it is no longer in the corpus and the corpus version has changed

#### Scenario: Deleting what is not there is reported

- **GIVEN** a path the corpus does not have
- **WHEN** an operator deletes it
- **THEN** the operator is told it was not found, and the corpus version is unchanged

#### Scenario: A failed write changes nothing

- **GIVEN** a write that cannot be committed
- **WHEN** it fails
- **THEN** neither the document nor the corpus version has changed

### Requirement: Authored content is validated by the loader

The system SHALL validate a submitted rule document by loading it with the same loader that loads the corpus at start-up, so that accepting a document means the deployment will load it, and no second implementation of validity can drift from the first.

A document the loader would reject SHALL be refused, and the refusal SHALL carry the loader's own reason, naming what to fix.

A refused document SHALL NOT be written, and SHALL NOT change the corpus version.

#### Scenario: A document the loader refuses is not written

- **GIVEN** a rule document the corpus loader rejects
- **WHEN** an operator submits it
- **THEN** it is refused with the loader's reason, and neither the corpus nor its version changes

#### Scenario: A pattern too expensive to match is refused

- **GIVEN** a rule document whose pattern exceeds the authored-pattern cost limit
- **WHEN** an operator submits it
- **THEN** it is refused, naming the field to fix

### Requirement: A rule matching everything is warned about

The system SHALL warn when a submitted document defines a detection with no discriminating predicate, and SHALL accept it.

Accepting is deliberate: a rule that matches everything is a foot-gun rather than an error, and an operator writing a broad hunting rule on purpose is doing something legitimate. Refusing it would substitute the system's judgement for the operator's on a question the system cannot answer.

A warning SHALL NOT prevent the write, and SHALL be reported to the operator that made it.

#### Scenario: A rule with no discriminating predicate warns

- **GIVEN** a document defining a detection that matches every event of its type
- **WHEN** an operator submits it
- **THEN** it is written, and the operator is warned that it matches everything

#### Scenario: A discriminating rule warns about nothing

- **GIVEN** a document defining a detection with a discriminating predicate
- **WHEN** an operator submits it
- **THEN** it is written with no warning

### Requirement: Every authoring change is attributable

The system SHALL record an audit entry for every rule-content mutation, attributing it to the acting principal, naming the document, and distinguishing a create or replace from a delete.

An audit entry SHALL be recorded for a mutation that took effect. A refused submission SHALL NOT be recorded as a mutation, because the corpus did not change.

#### Scenario: A write is attributed

- **GIVEN** an operator writes a rule document
- **WHEN** the write succeeds
- **THEN** an audit entry attributes the write to that operator and names the document

#### Scenario: A delete is attributed

- **GIVEN** an operator deletes a rule document
- **WHEN** the delete succeeds
- **THEN** an audit entry attributes the delete to that operator and names the document

#### Scenario: A refused submission is not a mutation

- **GIVEN** a submission the validator refuses
- **WHEN** it is refused
- **THEN** no mutation audit entry is recorded
