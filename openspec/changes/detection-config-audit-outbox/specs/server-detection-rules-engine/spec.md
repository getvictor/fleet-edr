## ADDED Requirements

### Requirement: Detection-config changes commit their audit entry

The audit entry for a detection-config change (creating or deleting an exclusion, changing a rule setting, or replacing the watched-path set) SHALL be committed in the same transaction as the change, so an audit reader can never find the change without its entry. Because the audit store belongs to another bounded context and cannot join that transaction, the entry SHALL be committed to an outbox and delivered to the audit store afterwards. Delivery MAY lag the change, SHALL be retried until it succeeds, and SHALL NOT drop an entry. A change that is refused or rolled back SHALL leave no entry. The delivered row SHALL carry the trace of the request that made the change.

A watched-path replacement's audit row SHALL report how many hosts the set was queued for and missed, which is known only after the change commits. Its entry SHALL therefore be withheld from delivery until the writer adds those counts. When the writer stops before adding them, the entry SHALL still be delivered, without the counts, once a bounded hold has passed.

#### Scenario: A change commits with its audit entry

- **GIVEN** an operator creating an exclusion, changing a rule setting, and deleting the exclusion
- **WHEN** each change commits
- **THEN** its audit entry has committed with it, naming the actor, the target, the reason, and the request's trace

#### Scenario: A delivery failure delays the audit row

- **GIVEN** an audit store that is unavailable when a detection-config change is made
- **WHEN** the change is made
- **THEN** the change succeeds and its entry stays in the outbox
- **AND** a later delivery, once the store is available, records the row and clears the entry

#### Scenario: A refused change leaves no audit entry

- **GIVEN** an exclusion for a match type its rule does not consult, a rule setting with an unknown mode, a deletion of a missing exclusion, or an invalid watched-path set
- **WHEN** the change is refused
- **THEN** no audit entry is left in the outbox

#### Scenario: A replacement's audit row reports its push

- **GIVEN** a watched-path replacement whose entry has committed with the set
- **WHEN** the push has not yet reported its host counts
- **THEN** the entry is not delivered
- **AND** once the counts are added, the delivered row carries them

#### Scenario: An entry whose writer stops is still delivered

- **GIVEN** a held entry whose writer never adds to it
- **WHEN** its hold passes
- **THEN** the entry is delivered as first written
