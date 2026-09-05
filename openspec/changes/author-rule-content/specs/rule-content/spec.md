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

The system SHALL validate a submitted rule document by loading the corpus it would produce with the same loader that loads the corpus at start-up, so that accepting a document means the deployment will load it, and no second implementation of validity can drift from the first.

Validation SHALL consider the whole document set the write would produce, not the submitted document alone. A rule's identity comes from its file stem, and two documents claiming one identity refuse the ENTIRE corpus rather than one document, so a document that is valid alone can still be the one that takes a deployment's rule set down to the copy embedded in its binary.

A document the loader would reject SHALL be refused, and the refusal SHALL carry the loader's own reason, naming what to fix.

The system SHALL distinguish a document that breaks the corpus from one the corpus can carry but this deployment cannot run. The first is refused. The second is accepted with a warning naming the file and the reason, because a corpus written for a fleet of sensors legitimately contains rules a given sensor cannot map, and refusing the write would stop an operator storing a rule their deployment would simply not run. A pattern above the affordable-matching limit falls in the second class: the rule is never loaded, so it cannot slow evaluation, and the operator is told which field exceeded which limit.

A proposed corpus in which NO document can run SHALL be refused, even though each individual rejection is only a warning, because storing it would leave the deployment falling back to the rule set embedded in its binary and silently discard what the operator published.

A refused document SHALL NOT be written, and SHALL NOT change the corpus version.

#### Scenario: A document the loader refuses is not written

- **GIVEN** a rule document the corpus loader rejects
- **WHEN** an operator submits it
- **THEN** it is refused with the loader's reason, and neither the corpus nor its version changes

#### Scenario: A document colliding with an existing rule identity is refused

- **GIVEN** a corpus already holding a rule whose identity a submitted document would also claim
- **WHEN** an operator submits it
- **THEN** it is refused, because accepting it would refuse the whole corpus at the next load

#### Scenario: A pattern too expensive to match is reported and does not run

- **GIVEN** a rule document whose pattern exceeds the affordable-matching limit, alongside a rule that runs
- **WHEN** an operator submits it
- **THEN** it is written, the rule is not loaded, and the operator is warned naming the field and the limit it exceeded

#### Scenario: A corpus in which nothing can run is refused

- **GIVEN** a proposed corpus whose every document this deployment would refuse
- **WHEN** an operator submits it
- **THEN** it is refused, because storing it would silently discard the corpus in force
