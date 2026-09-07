# rule-content Specification

## Purpose

The detection rules a deployment runs are stored as documents rather than built into the binary, so an upgrade delivers new detections and an operator can write, check, publish and restore their own. Each document records where it came from when it is stored, which is what keeps a shipped rule credited to the upstream project and an operator's own rule credited to them, on the catalog and on every alert either raises. The corpus identifies which shipped pack it holds, so a deployment can say whether it is running this build's rules, what an upgrade changed, and roll back to the previous generation without restoring a database backup.

## Requirements

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

The system SHALL refuse a submitted document whose path the loader does not inspect, including one nested beneath another document's path. Such a document would be stored, reported as successful, and never evaluated anywhere, which is the opposite of what an operator adding a rule intends.

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

### Requirement: A rule document records where it came from

The system SHALL record, for every stored rule document, whether it was shipped with the product or written by an operator.

Provenance SHALL be recorded when the document is stored, not derived from its path or its content. A rule's identity comes from its file stem rather than its path, and operators choose their own paths, so anything derived from a path is both contradicted by that and guessable by the operator it describes. How a document arrived is a fact only the store observes.

A document written through the authoring surface SHALL be recorded as the operator's, whatever path it is stored under.

#### Scenario: A seeded document is recorded as shipped with the product

- **GIVEN** an empty corpus and a product that ships rule content
- **WHEN** the corpus is seeded
- **THEN** every seeded document is recorded as having come from the product

#### Scenario: An authored document is recorded as the operator's

- **GIVEN** an operator writes a rule document
- **WHEN** it is stored
- **THEN** it is recorded as written by an operator, whatever path they chose

#### Scenario: Replacing a shipped document with an authored one changes its provenance

- **GIVEN** a document that was shipped with the product
- **WHEN** an operator writes over it
- **THEN** it is recorded as written by an operator, because it now is

### Requirement: An unrecognised provenance is refused

The system SHALL refuse rule content whose recorded provenance it does not recognise, both when storing it and when reading it back, rather than interpreting it as either known provenance.

An unrecognised value is not "written by an operator", so attribution would credit it upstream, and it is not "shipped with the product", so the pack identity would exclude it. Treating one as shipped would state a licence claim about content the system cannot vouch for.

#### Scenario: Content declaring an unrecognised provenance is not stored

- **GIVEN** a corpus holding rule content
- **WHEN** a replacement declares a provenance the system does not recognise
- **THEN** the replacement is refused and the stored content is unchanged

#### Scenario: A stored document with an unrecognised provenance is not interpreted

- **GIVEN** a stored document whose recorded provenance the system does not recognise
- **WHEN** the corpus is read
- **THEN** the read fails rather than crediting the document to an upstream project

### Requirement: Attribution follows recorded provenance

The system SHALL credit a rule according to where its document came from.

A rule shipped with the product SHALL keep crediting the upstream project and the rule's own author, which is what the licence its content carries requires.

A rule an operator wrote SHALL NOT be credited to an upstream project, and its alerts SHALL NOT carry that project's attribution. Crediting an upstream project for an operator's own work is false, and because that credit is how the system honours the licence upstream content carries, it also misstates the licensing of work not under it.

#### Scenario: An operator's rule is not credited upstream

- **GIVEN** a rule an operator wrote
- **WHEN** its attribution is shown
- **THEN** it is not credited to an upstream project

#### Scenario: An alert from an operator's rule carries no upstream attribution

- **GIVEN** an alert raised by a rule an operator wrote
- **WHEN** the alert records its attribution
- **THEN** it does not carry an upstream project's credit

#### Scenario: A shipped rule keeps its upstream credit

- **GIVEN** a rule shipped with the product
- **WHEN** its attribution is shown
- **THEN** it credits the upstream project and the rule's own author, as before

### Requirement: The corpus identifies which shipped pack it holds

The system SHALL identify the pack of shipped rule content a corpus holds, in a way that changes exactly when that content changes and requires no separate version to be maintained by hand.

The identity SHALL be derived from the shipped content itself, so that a deployment can determine whether it is running the pack in the build it is executing by comparing rather than by trusting a recorded label.

A corpus stored before the system recorded pack identity SHALL report no identity, rather than an identity computed on its behalf. Such a corpus holds some generation of shipped content and nothing recorded which, so reporting one would be inventing it. A caller comparing against the build's own pack SHALL treat the absence as "unknown, therefore not known to be current", which is distinct from the identity of a pack that is genuinely empty.

#### Scenario: The identity changes when the shipped content changes

- **GIVEN** two sets of shipped rule content that differ
- **WHEN** each is identified
- **THEN** the identities differ

#### Scenario: The identity is stable for unchanged content

- **GIVEN** the same shipped rule content
- **WHEN** it is identified more than once
- **THEN** the identity is the same each time

#### Scenario: A corpus stored before pack identity was recorded reports none

- **GIVEN** a corpus stored before the system recorded pack identity
- **WHEN** its pack identity is read
- **THEN** no identity is reported, which is distinct from the identity of a corpus holding no shipped content at all

#### Scenario: Content written by an operator does not change the pack identity

- **GIVEN** a corpus holding shipped content
- **WHEN** an operator adds a rule of their own
- **THEN** the pack identity is unchanged, because the shipped content is unchanged

#### Scenario: Changing a shipped rule changes the pack identity

- **GIVEN** a corpus holding shipped content
- **WHEN** an operator writes their own version of one of those rules, or deletes one
- **THEN** the pack identity changes, because the corpus no longer holds the shipped content it did

### Requirement: A replaced generation of shipped rule content can be restored

The system SHALL retain the generation of shipped rule content that installing a newer pack replaces, and SHALL be able to restore it.

Retention SHALL happen in the same operation as the replacement, so that a retained generation is always one that was actually replaced.

One generation SHALL be retained. Restoring it SHALL consume it, so a further rollback has nothing behind it and SHALL be reported rather than restoring the content already installed.

A rollback SHALL leave content the operator wrote untouched, including content written after the upgrade being rolled back, because rolling back a pack restores shipped content rather than undoing their work.

A rollback SHALL NOT restore shipped content whose RULE the operator has taken over since the upgrade, whatever path either is stored under. Their rule wins, as it does when shipped content is installed, and the shipped content withheld for that reason SHALL be reported.

A rollback SHALL survive a restart: the system SHALL NOT reinstall shipped content an operator rolled back from. What is declined SHALL be identified by the content that would be STORED rather than by the content a build carries, because those differ on a deployment holding an override and the looser comparison lets a build differing only in an overridden rule reinstall the rest of itself. The refusal SHALL apply to that content only, so a later build storing different content installs normally without the operator having to re-enable anything.

What is declined SHALL be the generation the upgrade installed, recorded when it was installed, so that changes an operator makes to shipped content afterwards do not alter it. A start that finds the content already installed but no generation recorded SHALL record it, so that a deployment upgraded before this was tracked can still name what a rollback declines. Otherwise deleting a shipped rule between the upgrade and the rollback records a decline describing content no build ever shipped, and the rejected generation reinstalls.

A retained generation SHALL be recognised by its recorded identity rather than by whether it contains any documents, so a generation that legitimately held no shipped rules can still be restored.

Rolling back when no generation is retained SHALL be reported, and SHALL NOT replace the shipped content with an empty set.

#### Scenario: The previous generation is restored

- **GIVEN** a deployment that installed a newer pack over an older one
- **WHEN** it rolls back
- **THEN** the shipped content is the older generation again, including rules the newer pack changed or dropped, and rules the newer pack added are gone

#### Scenario: A rollback is not undone by the next restart

- **GIVEN** a deployment that rolled back from the pack its build carries
- **WHEN** it starts again on that same build
- **THEN** the declined pack is not installed and the deployment is still running the generation it rolled back to

#### Scenario: A later pack still installs after a rollback

- **GIVEN** a deployment that rolled back from one pack
- **WHEN** it is started on a build carrying a different pack
- **THEN** that pack is installed, because the refusal applies to the declined pack rather than to installing in general

#### Scenario: An operator's own rules survive a rollback

- **GIVEN** a deployment holding rules the operator wrote
- **WHEN** it rolls back its shipped content
- **THEN** their rules are still stored and still recorded as theirs

#### Scenario: A rule the operator took over is not taken back

- **GIVEN** a deployment where the operator has taken over one of the rules in the retained generation, under any path
- **WHEN** it rolls back
- **THEN** their rule is unchanged, no two stored documents share an identity, and the shipped rule that was withheld is reported

#### Scenario: A corpus predating pack identity offers a rollback

- **GIVEN** a corpus stored before pack identity was recorded, whose identity is therefore unrecorded
- **WHEN** it installs a newer pack and its status is read
- **THEN** it reports a previous generation is available, and rolling back restores it

#### Scenario: A rollback holds against a build differing in an override

- **GIVEN** a deployment that rolled back, holding its own version of one of the shipped rules
- **WHEN** it is started on a build whose shipped content differs from the declined content only in that rule
- **THEN** nothing is installed, because that build would store the content the operator declined

#### Scenario: A rollback holds after the operator edits shipped content

- **GIVEN** a deployment that deleted one of the shipped rules a pack installed, and then rolled back
- **WHEN** it is started again on that same build
- **THEN** nothing is installed, because what it declined is the generation that was installed rather than the corpus as the edit left it

#### Scenario: An unrecorded generation is recorded on start

- **GIVEN** a deployment holding this build's shipped content with no generation recorded, as one upgraded before it was tracked would be
- **WHEN** it is started
- **THEN** no documents move, the generation it holds is recorded, and a rollback afterwards is not undone by the next start

#### Scenario: A generation with no shipped rules is still restorable

- **GIVEN** a corpus that held only the operator's own rules when a pack was first installed onto it
- **WHEN** it rolls back
- **THEN** the generation with no shipped rules is restored, leaving their own rules and none of the pack's

#### Scenario: Rolling back with nothing retained is reported

- **GIVEN** a deployment that has never installed a newer pack
- **WHEN** it rolls back
- **THEN** it is told no previous generation is retained, and its shipped content is unchanged

#### Scenario: A second rollback is refused

- **GIVEN** a deployment that has already rolled back
- **WHEN** it rolls back again
- **THEN** it is told no previous generation is retained

### Requirement: A deployment reports which shipped rule content it is running

The system SHALL report which generation of shipped rule content a deployment holds, which generation the running build carries, and which RULES differ between them.

Differences SHALL be reported by rule identity rather than by the path a document is stored under, because identity is what an operator recognises and what their per-rule tuning is keyed on.

Content the operator wrote SHALL be excluded from the comparison, so writing their own rule does not make a deployment appear out of date.

#### Scenario: The rules that differ are named

- **GIVEN** a deployment whose shipped content differs from the pack its build carries
- **WHEN** its pack status is read
- **THEN** it reports the deployment is not current, and names the rules added, removed and changed

#### Scenario: A current deployment reports no difference

- **GIVEN** a deployment holding exactly the shipped content its build carries
- **WHEN** its pack status is read
- **THEN** it reports the deployment is current and names no differences

#### Scenario: Their own rules do not make a deployment look out of date

- **GIVEN** a deployment holding this build's shipped content plus a rule the operator wrote
- **WHEN** its pack status is read
- **THEN** it reports the deployment is current, and their rule is not reported as a difference

### Requirement: Rule content is stored, and is the source the catalog loads from

The system SHALL store rule content durably, separately from the binary, and SHALL build its evaluatable rule set from that store rather than from content compiled in. Rule content SHALL be owned by a context distinct from the one that evaluates rules, which produces definitions and consumes nothing from the evaluator (ADR-0021).

Storing the content is what allows a detection to ship without a release, which is the whole purpose. It is also what makes rule content an aggregate rather than a projection of the catalog, and therefore what makes the separate ownership a boundary rather than a directory.

The stored content SHALL carry a version that changes whenever the content changes, and that version SHALL be readable without reading the content. A replica converges by noticing change, and noticing must be cheap enough to do on an interval where re-reading every document is not.

Replacing the stored content SHALL be atomic and SHALL replace it whole. Content is valid or invalid as a set: a rule removed from the source has to disappear rather than linger, and no reader may observe part of one version alongside part of another. The version SHALL advance in the same transaction, so a reader that sees a new version can only read the content that belongs to it.

The stored content SHALL be read back byte-identically, under the same identity the loader reads it by, so that storing content cannot change which detections run. That identity SHALL be the document's path, because rule identity is derived from it and collisions are detected by it before anything is parsed.

#### Scenario: The catalog loads the stored content

- **GIVEN** rule content in the store
- **WHEN** the rule set is built
- **THEN** it is built from the stored content
- **AND** the rules it yields are the same, and in the same order, as loading that content from the binary would give

#### Scenario: Replacing content removes what is no longer in it

- **GIVEN** stored content holding a rule that the replacement does not
- **WHEN** the content is replaced
- **THEN** that rule is no longer in the store
- **AND** the version has advanced

#### Scenario: The version is readable without reading the content

- **GIVEN** stored content
- **WHEN** a replica checks for change
- **THEN** it can read the version alone

### Requirement: An unavailable or unusable store leaves detections running

The system SHALL continue evaluating detections when the stored content cannot be used. Which content it evaluates depends on whether it has any: a system with nothing loaded SHALL fall back to the content compiled into the build, which is the same content the store would have been seeded with, and a system already evaluating content SHALL keep it.

Keeping the content in force SHALL NOT record the unusable content's version. Not recording it is what lets the system adopt the content as soon as it is corrected, since the poll keeps seeing a difference.

This leaves a divergence that is stated here rather than hidden. A replica that RESTARTS while unusable content is stored has no set in force to keep, so it falls back to the content compiled into its build and evaluates something different from its peers until the content is corrected. Making every replica adopt its build's content instead does not fix this and makes it worse: replicas part-way through a rolling deployment carry DIFFERENT built-in content, so they would record one version against different rules and report agreement they do not have. The condition is prevented upstream, by refusing content that cannot run before it is stored, rather than reconciled afterwards.

A deployment whose store is empty, unreachable, or holding content that fails to load SHALL therefore behave as it did before rule content was stored. The alternative is a server that starts with no detections because of a storage problem, which trades a bounded loss of the ability to change rules for an unbounded loss of the rules themselves.

Falling back for a REASON SHALL be reported. An empty store SHALL NOT be reported as a problem, because it is the expected state of a deployment that has not been seeded yet.

#### Scenario: Content that fails to load does not stop detection

- **GIVEN** stored content that cannot be loaded
- **WHEN** the rule set is built
- **THEN** the rules compiled into the build are evaluated instead
- **AND** the reason is reported

#### Scenario: An unseeded store is not an error

- **GIVEN** a store holding no content
- **WHEN** the rule set is built
- **THEN** the rules compiled into the build are evaluated
- **AND** nothing is reported as wrong

#### Scenario: A store that cannot be read keeps the set in force

- **GIVEN** a running system evaluating content it loaded successfully
- **WHEN** a later attempt to READ that content fails
- **THEN** the rule set already in force continues to be evaluated, unchanged
- **AND** the version it was built from is not advanced, so the next attempt retries

#### Scenario: Unusable stored content leaves the running set alone

- **GIVEN** a running system evaluating content it loaded successfully
- **WHEN** stored content is read successfully but yields no runnable rules, whether because it is empty, because it does not parse, or because every rule in it is refused
- **THEN** the rule set already in force continues to be evaluated
- **AND** that content's version is NOT recorded, so the corrected content is adopted when it arrives
- **AND** the condition is reported

#### Scenario: A system starting up has no running set to keep

- **GIVEN** stored content that yields no runnable rules, and a system with nothing yet loaded
- **WHEN** it builds its rule set
- **THEN** it evaluates the content compiled into the build, whether the content is empty or every rule in it is refused
- **AND** the two cases behave identically, because they are the same condition reached by different routes

### Requirement: Seeding never overwrites content that is already there

The system SHALL seed the store from the content compiled into the build only when the store holds no content. It SHALL NOT seed based on a comparison between the build's content and the stored content.

The distinction is what keeps authored content safe. Content in the store can be edited, so a seed that ran whenever the build looked newer would replace an operator's rules with the vendored set on the next restart. An empty store is the only state in which seeding is certainly not destroying something.

Seeding SHALL be safe to attempt on every start and on every replica, and a failure to seed SHALL NOT prevent the system from starting.

#### Scenario: An empty store is seeded

- **GIVEN** a store holding no content
- **WHEN** the system starts
- **THEN** the store holds the content compiled into the build

#### Scenario: A store holding content is left alone

- **GIVEN** a store holding content that differs from the build's
- **WHEN** the system starts again
- **THEN** the stored content is unchanged

### Requirement: A running server picks up changed content

The system SHALL adopt content published while it is running, without a restart. Each replica SHALL converge on the published content on its own, and SHALL do so by polling a version counter rather than by re-reading the content itself.

Polling the counter is what makes this affordable. The compiled rule set is derived state that every replica builds for itself, so a publish on one replica is invisible to its peers until each re-reads (ADR-0010), and a poll that re-read, parsed and compiled the whole corpus every interval would spend the cost of a publish on every replica continuously. Reading a single-row counter and comparing it against the version the loaded set was built from confines that cost to an actual change.

The version SHALL be read BEFORE the content, and the ordering is a correctness requirement rather than a preference. The two reads cannot be made atomic, so a publish landing between them yields a mismatched pair either way. Reading the version first pairs newer content with an older version, which the next poll sees as a difference and corrects. The reverse pairs older content with the newer version, which the next poll reads as current, leaving content in force that the system believes is up to date and nothing to correct it.

Adopting content SHALL bring every consumer derived from the rule set with it. The rule set has more than one consumer: the operator-facing catalog, the validation that rejects an exclusion naming a rule that does not exist, and the evaluation engine's own compiled indices. A consumer left holding a set built from withdrawn content produces no error of its own, so this is stated as a requirement rather than left to each call site: the catalog would list rules that are never evaluated, and the validation would reject an exclusion for a rule that now exists.

Replacing the content SHALL advance the version counter in the same transaction that writes the content. The guarantee that buys is ONE-WAY and the direction matters: a reader can never observe the new version paired with the previous content. It does not make a version read and a content read atomic with each other, so a reader taking them separately can still pair an older version with newer content, which is precisely the pairing the ordering above is chosen to tolerate.

A replica that has just started SHALL NOT assume the set it built is current. It has content but not the version that produced it, so its first poll SHALL adopt the stored generation and record its version, rather than treating an unknown version as a match. Assuming currency would leave a replica that started during a publish serving the older content until the NEXT publish, which is indistinguishable from working correctly.

#### Scenario: Content published elsewhere is picked up without a restart

- **GIVEN** two replicas evaluating the same stored content
- **WHEN** one of them publishes different content
- **THEN** the other adopts it without being restarted
- **AND** the replica that has not yet re-read continues to evaluate what it loaded, because the compiled set is per-replica

#### Scenario: An unchanged version does not re-read the content

- **GIVEN** a replica whose loaded content is current
- **WHEN** it polls for changes
- **THEN** it reads only the version counter
- **AND** the content is neither re-read nor recompiled

#### Scenario: The version is read before the content

- **GIVEN** content being adopted
- **WHEN** the version and the content are read
- **THEN** the version is read first, so that content newer than the version it is stamped with is corrected by the next poll

#### Scenario: A replica adopts stored content on its first poll

- **GIVEN** a replica that has just started and built a rule set
- **WHEN** it polls for changes for the first time
- **THEN** it adopts the stored content and records the version that produced it
- **AND** it does not treat the set it started with as already current

#### Scenario: The rule set in force is replaced wholesale

- **GIVEN** a rule set being adopted
- **WHEN** it is put in force
- **THEN** every consumer derived from the rule set is rebuilt from it
- **AND** no consumer continues to answer from the previous set

### Requirement: A build installs its shipped rule content

The system SHALL install the shipped rule content carried by the running build over the shipped rule content the corpus holds, so that a deployment upgraded to obtain new detections actually runs them.

Seeding SHALL remain guarded on an empty corpus, and this SHALL be a separate operation, because relaxing that guard would overwrite an operator's own rules on every restart.

Installing SHALL replace only the shipped content. Content an operator wrote SHALL survive, including content written at a path the pack also ships, because taking that path back would discard the rule they wrote and credit its replacement to a project that did not write it.

Installing SHALL NOT store shipped content whose RULE an operator already owns, whatever path either is stored under and whatever case either is written in. A rule is identified by its file stem rather than its path, so two documents resolving to one identity are the same rule stored twice, and a corpus holding both does not load at all: every rule on the deployment stops, not only the pair. Shipped content withheld for this reason SHALL be reported.

An operator's per-rule tuning SHALL survive installing a pack.

Installing SHALL be idempotent: installing the content a corpus already holds SHALL change nothing, and SHALL NOT advance the corpus version.

A pack whose content declares itself to be an operator's SHALL be refused, because shipped content is what a pack is.

A build carrying no shipped rule content SHALL leave the stored content alone rather than removing it.

#### Scenario: A newer pack replaces the shipped content

- **GIVEN** a corpus holding shipped rule content
- **WHEN** a build carrying different shipped content is started
- **THEN** the stored shipped content is replaced by the build's, including content the newer pack adds, and content the newer pack no longer carries is removed

#### Scenario: An operator's own rule survives

- **GIVEN** a corpus holding shipped content and a rule the operator wrote
- **WHEN** a build carrying different shipped content is started
- **THEN** the operator's rule is still stored, still recorded as theirs, and still carries the content they wrote

#### Scenario: A path the operator has taken over stays theirs

- **GIVEN** an operator has written their own version of a rule that shipped, at the path it shipped under
- **WHEN** a build that still ships that path is started
- **THEN** the stored document is still the operator's, with the content they wrote

#### Scenario: A pack rule colliding with an operator's rule is not installed

- **GIVEN** an operator's own rule, and a build shipping a rule of the same identity stored under a different path
- **WHEN** the build is started
- **THEN** the shipped rule is not stored, the operator's rule is unchanged, no two stored documents share an identity, and the shipped rule that was withheld is reported

#### Scenario: A pack rule differing only in case is not installed

- **GIVEN** an operator's own rule, and a build shipping a rule whose identity differs from it only in letter case
- **WHEN** the build is started
- **THEN** the shipped rule is not stored, because rule identities are compared the way the records keyed by them are compared, which is without regard to case

#### Scenario: An operator's tuning survives

- **GIVEN** a rule whose mode and severity an operator has set
- **WHEN** the shipped content is replaced by a newer pack carrying that rule
- **THEN** the mode and severity the operator set still apply

#### Scenario: Installing the same content again changes nothing

- **GIVEN** a corpus already holding the shipped content this build carries
- **WHEN** the build is started again
- **THEN** nothing is written and the corpus version is unchanged

#### Scenario: Installing is unaffected by an operator's override

- **GIVEN** a corpus holding this build's shipped content, with one of those rules overridden by the operator
- **WHEN** the build is started again
- **THEN** nothing is written and the corpus version is unchanged

#### Scenario: A pack declaring authored content is refused

- **GIVEN** shipped content in which a document declares itself to be an operator's
- **WHEN** it is installed
- **THEN** it is refused and the stored content is unchanged

#### Scenario: A build carrying no shipped content leaves the corpus alone

- **GIVEN** a corpus holding shipped content
- **WHEN** a build carrying no shipped rule content is started
- **THEN** the stored content is unchanged

### Requirement: A rule that discriminates nothing is warned about

The system SHALL warn when submitted rule content defines a search that every event carrying its fields satisfies, and SHALL store the content.

Warning rather than refusing is deliberate. An operator writing a deliberately broad hunting rule is doing something legitimate, and refusing it would substitute the system's judgement for theirs on a question the system cannot answer, which is whether they meant it.

The warning SHALL name the searches responsible, because an operator fixing it needs to know which part of their rule to look at.

The system SHALL NOT warn about a pattern that restricts the value in any way, including one that requires at least one character and one that requires the value to be empty. A warning that fires on rules an operator wrote deliberately is ignored, and then reports nothing when it matters.

The system SHALL warn only where such a search is ASSERTED by the rule's condition, and SHALL NOT warn where the condition negates it or does not use it at all. A search matching everything contributes nothing where it is asserted, but negating it makes it match nothing, which is the most discriminating predicate there is and a different concern entirely: a rule that can never fire. A search the condition never mentions cannot make the rule broad.

The system SHALL NOT claim to decide this for a regular-expression pattern. Whether a regular expression matches every value is a question about a different matcher, and answering it wrongly in the reassuring direction would be worse than not answering.

#### Scenario: A search matching every value is warned about

- **GIVEN** a submitted rule whose search matches any value of its field
- **WHEN** it is validated
- **THEN** it is accepted, and the warning names that search

#### Scenario: A negated match-everything search is not warned about

- **GIVEN** a submitted rule whose condition negates a search that matches every value
- **WHEN** it is validated
- **THEN** it is accepted with no such warning, because negating it makes it match nothing

#### Scenario: A search the condition does not use is not warned about

- **GIVEN** a submitted rule declaring a search that matches everything but never referencing it in the condition
- **WHEN** it is validated
- **THEN** it is accepted with no such warning, because an unreferenced search is never evaluated

#### Scenario: A discriminating rule is not warned about

- **GIVEN** a submitted rule whose searches all restrict the values they match
- **WHEN** it is validated
- **THEN** it is accepted with no such warning

#### Scenario: A pattern requiring at least one character is not warned about

- **GIVEN** a submitted rule whose pattern requires the value to be non-empty
- **WHEN** it is validated
- **THEN** it is accepted with no such warning, because it restricts what matches

#### Scenario: A pattern requiring an empty value is not warned about

- **GIVEN** a submitted rule whose pattern matches only an empty value
- **WHEN** it is validated
- **THEN** it is accepted with no such warning, because it is the narrowest pattern rather than the broadest

### Requirement: A change is told only about itself

The system SHALL report, for a change to rule content, only the advisory findings about the document being changed.

Validation covers the whole proposed corpus and SHALL continue to, because a document that is valid alone can still be the change that stops the corpus loading. What is scoped is attribution, not validation: findings about documents the change did not touch belong to the corpus rather than to the change.

An audit entry for a change SHALL carry only findings about that change. A reviewer reading it has to be able to trust that what it says is about the change it names, and a record that attributes an unrelated document's problem to someone's edit misinforms the one surface that exists to be trusted.

#### Scenario: A write reports only findings about the document written

- **GIVEN** a proposed corpus with an advisory finding about a document the operator is not changing
- **WHEN** they write a different document
- **THEN** they are told only about the document they wrote

#### Scenario: A deletion reports no findings about the document removed

- **GIVEN** an operator deletes a document
- **WHEN** the deletion takes effect
- **THEN** no advisory finding is reported for it, because it is no longer in the corpus

#### Scenario: An audit entry carries only findings about its own change

- **GIVEN** a change made while the corpus has findings about other documents
- **WHEN** the audit entry is recorded
- **THEN** it carries only the findings about the changed document
