# Rule content: operator authoring delta

## ADDED Requirements

### Requirement: The read surface does not carry the write surface

The system SHALL NOT make rule-content writes reachable from the handle it publishes for reading. A read handle whose underlying type also carries the write operations can be converted to one that writes, so every guarantee the authoring path makes about validation would hold only for callers that chose to use it.

#### Scenario: A read handle cannot be converted into a write handle

- **GIVEN** the handle the system publishes for reading rule content
- **WHEN** a consumer attempts to convert it to one that writes
- **THEN** the conversion does not succeed

### Requirement: Operators author rule content

The system SHALL let an authorised operator create, replace, and delete a rule document in the stored corpus.

A write SHALL make the document and the corpus version durable together, so a replica that polls the version never learns of a change it cannot then read.

A write SHALL be applied only to the corpus state it was validated against, and SHALL be refused when the corpus has moved since. Validation and the write are otherwise a check-then-act: two operators writing documents whose rule identities collide would each validate against a corpus lacking the other, both pass, and the corpus that lands would claim one identity twice, which every replica then refuses entirely. A write SHALL be applied atomically: the document and the version change together, or neither changes. There is no state in which one moved and the other did not.

A caller that observes a failure SHALL NOT conclude the write did not apply. Committing is not an operation whose outcome is always reported: a commit can succeed and the response be lost, leaving the caller with an error for a write that took effect. Atomicity is a property of the corpus, not a promise about what an error means, and the corpus version is the authority on what actually happened.

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

#### Scenario: A write that fails before it is applied changes nothing

- **GIVEN** a write that fails before it is applied
- **WHEN** it fails
- **THEN** neither the document nor the corpus version has changed

#### Scenario: A write validated against a corpus that has since moved is refused

- **GIVEN** a write validated against one state of the corpus
- **AND** another write that lands first and changes the corpus
- **WHEN** the first write is applied
- **THEN** it is refused, and neither the documents nor the version change

### Requirement: Authored content is validated by the loader

The system SHALL validate a submitted rule document by loading the corpus it would produce with the same loader that loads the corpus at start-up, so that accepting a document means the deployment will load it, and no second implementation of validity can drift from the first.

Validation SHALL consider the whole document set the write would produce, not the submitted document alone. A rule's identity comes from its file stem, and two documents claiming one identity refuse the ENTIRE corpus rather than one document, so a document that is valid alone can still be the one that takes a deployment's rule set down to the copy embedded in its binary.

A document the loader would reject SHALL be refused, and the refusal SHALL carry the loader's own reason, naming what to fix.

The system SHALL distinguish a document that breaks the corpus from one the corpus can carry but this deployment cannot run. The first is refused. The second is accepted with a warning naming the file and the reason, because a corpus written for a fleet of sensors legitimately contains rules a given sensor cannot map, and refusing the write would stop an operator storing a rule their deployment would simply not run. A pattern above the affordable-matching limit falls in the second class: the rule is never loaded, so it cannot slow evaluation, and the operator is told which field exceeded which limit.

Rule identities SHALL be compared the way the system that stores them compares them, not the way the language that loads them does. Identity is persisted alongside per-rule settings and alert deduplication, where comparison is case-insensitive, so two documents whose identities differ only by case name one rule everywhere it matters: tuning one would tune the other and their alerts would deduplicate together, while the corpus itself would show two distinct rules.

The system SHALL refuse a submitted document whose rule identifier is already used by a rule the deployment ships in code. Stored rules are added to those, and nothing downstream distinguishes the two: per-rule settings and alert deduplication are keyed by the identifier, so the pair could not be tuned or triaged separately while the catalog listed both.

Rule identifiers SHALL be restricted to a character set over which case is the only way two identifiers can differ and still compare equal where they are stored. Reproducing an accent-insensitive collation outside the store is not reliably possible, and every approximation fails in the direction that admits a colliding pair, so the identifier space is narrowed rather than the comparison widened.

The system SHALL refuse a submitted document whose path the loader does not inspect. Such a document would be stored, reported as successful, and never evaluated anywhere, which is the opposite of what an operator adding a rule intends.

The system SHALL bound the size of a submitted document, the length of its path, and the number of documents in a corpus. The path bound matches what storage accepts, so a path too long to store is refused with a reason naming what to shorten rather than failing later as an internal error. The whole corpus is revalidated on every edit and reparsed by every replica whenever it changes, so an operator submitting nothing but valid rules could otherwise make both arbitrarily expensive, which is a denial of service requiring no malformed input.

A proposed corpus in which NO document can run SHALL be refused, and that includes a proposal to store nothing at all. An empty corpus does not mean "no rules": the system keeps the rule set already in force when the store is empty, so rules an operator deleted would go on running while the deletion reported success, with no surface anywhere that would show it.

A refused document SHALL NOT be written, and SHALL NOT change the corpus version.

#### Scenario: A document the loader refuses is not written

- **GIVEN** a rule document the corpus loader rejects
- **WHEN** an operator submits it
- **THEN** it is refused with the loader's reason, and neither the corpus nor its version changes

#### Scenario: A document colliding with an existing rule identity is refused

- **GIVEN** a corpus already holding a rule whose identity a submitted document would also claim
- **WHEN** an operator submits it
- **THEN** it is refused, because accepting it would refuse the whole corpus at the next load

#### Scenario: An identifier already used by a shipped rule is refused

- **GIVEN** a proposed document whose rule identifier is already used by a rule the deployment ships
- **WHEN** an operator submits it
- **THEN** it is refused, because the two could not be tuned or triaged separately

#### Scenario: An identifier outside the permitted character set is refused

- **GIVEN** a proposed corpus containing a rule identifier outside the permitted character set
- **WHEN** an operator submits it
- **THEN** it is refused, because whether it collides with another identifier cannot be decided outside the store

#### Scenario: Two rule identities differing only by case are refused

- **GIVEN** a proposed corpus with two documents whose rule identities differ only by case
- **WHEN** an operator submits it
- **THEN** it is refused, because the stores that record per-rule settings and deduplicate alerts cannot tell the two apart

#### Scenario: A document the loader would not read is refused

- **GIVEN** a submitted document whose path the corpus loader does not inspect
- **WHEN** an operator submits it
- **THEN** it is refused, rather than stored as a rule that is never evaluated

#### Scenario: A pattern too expensive to match is reported and does not run

- **GIVEN** a rule document whose pattern exceeds the affordable-matching limit, alongside a rule that runs
- **WHEN** an operator submits it
- **THEN** it is written, the rule is not loaded, and the operator is warned naming the field and the limit it exceeded

#### Scenario: An oversized corpus is refused

- **GIVEN** a proposed corpus exceeding the permitted document size, path length, or document count
- **WHEN** an operator submits it
- **THEN** it is refused before it is parsed

#### Scenario: A corpus in which nothing can run is refused

- **GIVEN** a proposed corpus whose every document this deployment would refuse
- **WHEN** an operator submits it
- **THEN** it is refused, because storing it would silently discard the corpus in force
