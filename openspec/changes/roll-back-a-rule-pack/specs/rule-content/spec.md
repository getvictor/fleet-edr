# Rule content: roll back a rule pack delta

## ADDED Requirements

### Requirement: A replaced generation of shipped rule content can be restored

The system SHALL retain the generation of shipped rule content that installing a newer pack replaces, and SHALL be able to restore it.

Retention SHALL happen in the same operation as the replacement, so that a retained generation is always one that was actually replaced.

One generation SHALL be retained. Restoring it SHALL consume it, so a further rollback has nothing behind it and SHALL be reported rather than restoring the content already installed.

A rollback SHALL leave content the operator wrote untouched, including content written after the upgrade being rolled back, because rolling back a pack restores shipped content rather than undoing their work.

A rollback SHALL NOT restore shipped content whose RULE the operator has taken over since the upgrade, whatever path either is stored under. Their rule wins, as it does when shipped content is installed, and the shipped content withheld for that reason SHALL be reported.

A rollback SHALL survive a restart: the system SHALL NOT reinstall a pack an operator rolled back from. That refusal SHALL apply to the declined pack only, so shipped content from a later build installs normally without the operator having to re-enable anything.

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
