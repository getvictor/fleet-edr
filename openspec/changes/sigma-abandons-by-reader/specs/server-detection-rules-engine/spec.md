## ADDED Requirements

### Requirement: Sigma abandons are charged to the rule that read the process

A Sigma-backed rule SHALL record an abandon when the process record of the event's subject is still missing past the materialization grace and the rule's decision depended on it: its detection matched, so there is no process to name in the finding, or its detection read the field the engine resolves from the process graph (`Image` on a file event, `ParentImage` on an exec) and did not match. A rule whose detection decided on the event's own fields SHALL NOT be charged, even when another rule in the same batch read the same event's process. A subject that materialized, whose parent did not, SHALL NOT be charged, since a parent may predate the capture.

The parent of an exec's subject SHALL be found from the subject's own record, read through the same grace as the subject: inside the grace a missing subject SHALL make the evaluation retryable rather than leave the parent's image absent.

#### Scenario: A match with no process to name is counted

- **GIVEN** a Sigma rule whose detection matches an event whose subject never materialized
- **WHEN** the rule evaluates the event past the grace
- **THEN** no finding is produced and one abandon is recorded against the rule

#### Scenario: Only the rule that read the process is charged

- **GIVEN** two Sigma rules evaluating the same file event whose subject never materialized, one whose detection reads `Image` and one whose detection reads only the file path
- **WHEN** both evaluate the event past the grace
- **THEN** an abandon is recorded against the rule that read `Image` and none against the other

#### Scenario: A missing parent is not an abandon

- **GIVEN** an exec whose subject materialized and whose parent did not
- **WHEN** a Sigma rule reading `ParentImage` evaluates it
- **THEN** no abandon is recorded

#### Scenario: A missing subject hides the parent too

- **GIVEN** an exec whose subject never materialized
- **WHEN** a Sigma rule reading `ParentImage` evaluates it
- **THEN** past the grace an abandon is recorded against the rule
- **AND** inside the grace the evaluation fails with the retryable not-yet-materialized error
