## REMOVED Requirements

### Requirement: An operator can see and restore the shipped rule content

**Reason**: Renamed only. The title said "shipped", which describes a release rather than where a rule came from. Re-stated below as "An operator can see and restore the built-in rule content" with every scenario carried across unchanged apart from the same substitution in their prose. No behaviour changes and nothing is lost.

**Migration**: None. The tests covering these scenarios move their markers to the renamed ids in this change.

### Requirement: The corpus identifies which shipped pack it holds

**Reason**: Renamed only. The title said "shipped", which describes a release rather than where a rule came from. Re-stated below as "The corpus identifies which built-in pack it holds" with every scenario carried across unchanged apart from the same substitution in their prose. No behaviour changes and nothing is lost.

**Migration**: None. The tests covering these scenarios move their markers to the renamed ids in this change.

### Requirement: A replaced generation of shipped rule content can be restored

**Reason**: Renamed only. The title said "shipped", which describes a release rather than where a rule came from. Re-stated below as "A replaced generation of built-in content can be restored" with every scenario carried across unchanged apart from the same substitution in their prose. No behaviour changes and nothing is lost.

**Migration**: None. The tests covering these scenarios move their markers to the renamed ids in this change.

### Requirement: A deployment reports which shipped rule content it is running

**Reason**: Renamed only. The title said "shipped", which describes a release rather than where a rule came from. Re-stated below as "A deployment reports which built-in content it runs" with every scenario carried across unchanged apart from the same substitution in their prose. No behaviour changes and nothing is lost.

**Migration**: None. The tests covering these scenarios move their markers to the renamed ids in this change.

### Requirement: A build installs its shipped rule content

**Reason**: Renamed only. The title said "shipped", which describes a release rather than where a rule came from. Re-stated below as "A build installs its built-in rule content" with every scenario carried across unchanged apart from the same substitution in their prose. No behaviour changes and nothing is lost.

**Migration**: None. The tests covering these scenarios move their markers to the renamed ids in this change.

## ADDED Requirements

### Requirement: An operator can see and restore the built-in rule content


The system SHALL let an authorized operator read which generation of built-in rule content a deployment runs, which generation the running build carries, and which rules differ between them, and SHALL report whether a previous generation is available to restore rather than requiring that be inferred.

The system SHALL let an authorized operator restore the previous generation. That change SHALL require a stated reason and SHALL be recorded against whoever made it, under an action of its own rather than one describing a change to a single document, because it replaces every built-in rule at once.

A restore that is refused SHALL NOT be recorded, because nothing changed.

Built-in rules not restored because the operator has taken that rule over SHALL be reported to the caller and recorded, so that content the deployment is deliberately not running is visible rather than absent without explanation.

Reading SHALL be authorized as a read and restoring as a change to rule content, matching the surface that serves the individual documents.

#### Scenario: An operator reads which built-in rules are installed

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
- **THEN** the response names the built-in rule that was not restored

### Requirement: The corpus identifies which built-in pack it holds


The system SHALL identify the pack of built-in rule content a corpus holds, in a way that changes exactly when that content changes and requires no separate version to be maintained by hand.

The identity SHALL be derived from the built-in content itself, so that a deployment can determine whether it is running the pack in the build it is executing by comparing rather than by trusting a recorded label.

A corpus stored before the system recorded pack identity SHALL report no identity, rather than an identity computed on its behalf. Such a corpus holds some generation of built-in content and nothing recorded which, so reporting one would be inventing it. A caller comparing against the build's own pack SHALL treat the absence as "unknown, therefore not known to be current", which is distinct from the identity of a pack that is genuinely empty.

#### Scenario: The identity changes when the built-in content changes

- **GIVEN** two sets of built-in rule content that differ
- **WHEN** each is identified
- **THEN** the identities differ

#### Scenario: The identity is stable for unchanged content

- **GIVEN** the same built-in rule content
- **WHEN** it is identified more than once
- **THEN** the identity is the same each time

#### Scenario: A corpus stored before pack identity was recorded reports none

- **GIVEN** a corpus stored before the system recorded pack identity
- **WHEN** its pack identity is read
- **THEN** no identity is reported, which is distinct from the identity of a corpus holding no built-in content at all

#### Scenario: Content written by an operator does not change the pack identity

- **GIVEN** a corpus holding built-in content
- **WHEN** an operator adds a rule of their own
- **THEN** the pack identity is unchanged, because the built-in content is unchanged

#### Scenario: Changing a built-in rule changes the pack identity

- **GIVEN** a corpus holding built-in content
- **WHEN** an operator writes their own version of one of those rules, or deletes one
- **THEN** the pack identity changes, because the corpus no longer holds the built-in content it did

### Requirement: A replaced generation of built-in content can be restored


The system SHALL retain the generation of built-in rule content that installing a newer pack replaces, and SHALL be able to restore it.

Retention SHALL happen in the same operation as the replacement, so that a retained generation is always one that was actually replaced.

One generation SHALL be retained. Restoring it SHALL consume it, so a further rollback has nothing behind it and SHALL be reported rather than restoring the content already installed.

A rollback SHALL leave content the operator wrote untouched, including content written after the upgrade being rolled back, because rolling back a pack restores built-in content rather than undoing their work.

A rollback SHALL NOT restore built-in content whose RULE the operator has taken over since the upgrade, whatever path either is stored under. Their rule wins, as it does when built-in content is installed, and the built-in content withheld for that reason SHALL be reported.

A rollback SHALL survive a restart: the system SHALL NOT reinstall built-in content an operator rolled back from. What is declined SHALL be identified by the content that would be STORED rather than by the content a build carries, because those differ on a deployment holding an override and the looser comparison lets a build differing only in an overridden rule reinstall the rest of itself. The refusal SHALL apply to that content only, so a later build storing different content installs normally without the operator having to re-enable anything.

What is declined SHALL be the generation the upgrade installed, recorded when it was installed, so that changes an operator makes to built-in content afterwards do not alter it. A start that finds the content already installed but no generation recorded SHALL record it, so that a deployment upgraded before this was tracked can still name what a rollback declines. Otherwise deleting a built-in rule between the upgrade and the rollback records a decline describing content no build ever shipped, and the rejected generation reinstalls.

A retained generation SHALL be recognised by its recorded identity rather than by whether it contains any documents, so a generation that legitimately held no built-in rules can still be restored.

Rolling back when no generation is retained SHALL be reported, and SHALL NOT replace the built-in content with an empty set.

#### Scenario: The previous generation is restored

- **GIVEN** a deployment that installed a newer pack over an older one
- **WHEN** it rolls back
- **THEN** the built-in content is the older generation again, including rules the newer pack changed or dropped, and rules the newer pack added are gone

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
- **WHEN** it rolls back its built-in content
- **THEN** their rules are still stored and still recorded as theirs

#### Scenario: A rule the operator took over is not taken back

- **GIVEN** a deployment where the operator has taken over one of the rules in the retained generation, under any path
- **WHEN** it rolls back
- **THEN** their rule is unchanged, no two stored documents share an identity, and the built-in rule that was withheld is reported

#### Scenario: A corpus predating pack identity offers a rollback

- **GIVEN** a corpus stored before pack identity was recorded, whose identity is therefore unrecorded
- **WHEN** it installs a newer pack and its status is read
- **THEN** it reports a previous generation is available, and rolling back restores it

#### Scenario: A rollback holds against a build differing in an override

- **GIVEN** a deployment that rolled back, holding its own version of one of the built-in rules
- **WHEN** it is started on a build whose built-in content differs from the declined content only in that rule
- **THEN** nothing is installed, because that build would store the content the operator declined

#### Scenario: A rollback holds after the operator edits built-in content

- **GIVEN** a deployment that deleted one of the built-in rules a pack installed, and then rolled back
- **WHEN** it is started again on that same build
- **THEN** nothing is installed, because what it declined is the generation that was installed rather than the corpus as the edit left it

#### Scenario: An unrecorded generation is recorded on start

- **GIVEN** a deployment holding this build's built-in content with no generation recorded, as one upgraded before it was tracked would be
- **WHEN** it is started
- **THEN** no documents move, the generation it holds is recorded, and a rollback afterwards is not undone by the next start

#### Scenario: A generation with no built-in rules is still restorable

- **GIVEN** a corpus that held only the operator's own rules when a pack was first installed onto it
- **WHEN** it rolls back
- **THEN** the generation with no built-in rules is restored, leaving their own rules and none of the pack's

#### Scenario: Rolling back with nothing retained is reported

- **GIVEN** a deployment that has never installed a newer pack
- **WHEN** it rolls back
- **THEN** it is told no previous generation is retained, and its built-in content is unchanged

#### Scenario: A second rollback is refused

- **GIVEN** a deployment that has already rolled back
- **WHEN** it rolls back again
- **THEN** it is told no previous generation is retained

### Requirement: A deployment reports which built-in content it runs


The system SHALL report which generation of built-in rule content a deployment holds, which generation the running build carries, and which RULES differ between them.

Differences SHALL be reported by rule identity rather than by the path a document is stored under, because identity is what an operator recognises and what their per-rule tuning is keyed on.

Content the operator wrote SHALL be excluded from the comparison, so writing their own rule does not make a deployment appear out of date.

#### Scenario: The rules that differ are named

- **GIVEN** a deployment whose built-in content differs from the pack its build carries
- **WHEN** its pack status is read
- **THEN** it reports the deployment is not current, and names the rules added, removed and changed

#### Scenario: A current deployment reports no difference

- **GIVEN** a deployment holding exactly the built-in content its build carries
- **WHEN** its pack status is read
- **THEN** it reports the deployment is current and names no differences

#### Scenario: Their own rules do not make a deployment look out of date

- **GIVEN** a deployment holding this build's built-in content plus a rule the operator wrote
- **WHEN** its pack status is read
- **THEN** it reports the deployment is current, and their rule is not reported as a difference

### Requirement: A build installs its built-in rule content


The system SHALL install the built-in rule content carried by the running build over the built-in rule content the corpus holds, so that a deployment upgraded to obtain new detections actually runs them.

Seeding SHALL remain guarded on an empty corpus, and this SHALL be a separate operation, because relaxing that guard would overwrite an operator's own rules on every restart.

Installing SHALL replace only the built-in content. Content an operator wrote SHALL survive, including content written at a path the pack also ships, because taking that path back would discard the rule they wrote and credit its replacement to a project that did not write it.

Installing SHALL NOT store built-in content whose RULE an operator already owns, whatever path either is stored under and whatever case either is written in. A rule is identified by its file stem rather than its path, so two documents resolving to one identity are the same rule stored twice, and a corpus holding both does not load at all: every rule on the deployment stops, not only the pair. Built-in content withheld for this reason SHALL be reported.

An operator's per-rule tuning SHALL survive installing a pack.

Installing SHALL be idempotent: installing the content a corpus already holds SHALL change nothing, and SHALL NOT advance the corpus version.

A pack whose content declares itself to be an operator's SHALL be refused, because built-in content is what a pack is.

A build carrying no built-in rule content SHALL leave the stored content alone rather than removing it.

#### Scenario: A newer pack replaces the built-in content

- **GIVEN** a corpus holding built-in rule content
- **WHEN** a build carrying different built-in content is started
- **THEN** the stored built-in content is replaced by the build's, including content the newer pack adds, and content the newer pack no longer carries is removed

#### Scenario: An operator's own rule survives

- **GIVEN** a corpus holding built-in content and a rule the operator wrote
- **WHEN** a build carrying different built-in content is started
- **THEN** the operator's rule is still stored, still recorded as theirs, and still carries the content they wrote

#### Scenario: A path the operator has taken over stays theirs

- **GIVEN** an operator has written their own version of a rule that shipped, at the path it shipped under
- **WHEN** a build that still ships that path is started
- **THEN** the stored document is still the operator's, with the content they wrote

#### Scenario: A pack rule colliding with an operator's rule is not installed

- **GIVEN** an operator's own rule, and a build shipping a rule of the same identity stored under a different path
- **WHEN** the build is started
- **THEN** the built-in rule is not stored, the operator's rule is unchanged, no two stored documents share an identity, and the built-in rule that was withheld is reported

#### Scenario: A pack rule differing only in case is not installed

- **GIVEN** an operator's own rule, and a build shipping a rule whose identity differs from it only in letter case
- **WHEN** the build is started
- **THEN** the built-in rule is not stored, because rule identities are compared the way the records keyed by them are compared, which is without regard to case

#### Scenario: An operator's tuning survives

- **GIVEN** a rule whose mode and severity an operator has set
- **WHEN** the built-in content is replaced by a newer pack carrying that rule
- **THEN** the mode and severity the operator set still apply

#### Scenario: Installing the same content again changes nothing

- **GIVEN** a corpus already holding the built-in content this build carries
- **WHEN** the build is started again
- **THEN** nothing is written and the corpus version is unchanged

#### Scenario: Installing is unaffected by an operator's override

- **GIVEN** a corpus holding this build's built-in content, with one of those rules overridden by the operator
- **WHEN** the build is started again
- **THEN** nothing is written and the corpus version is unchanged

#### Scenario: A pack declaring authored content is refused

- **GIVEN** built-in content in which a document declares itself to be an operator's
- **WHEN** it is installed
- **THEN** it is refused and the stored content is unchanged

#### Scenario: A build carrying no built-in content leaves the corpus alone

- **GIVEN** a corpus holding built-in content
- **WHEN** a build carrying no built-in rule content is started
- **THEN** the stored content is unchanged
