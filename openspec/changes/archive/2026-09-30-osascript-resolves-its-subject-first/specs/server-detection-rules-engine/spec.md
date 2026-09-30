## ADDED Requirements

### Requirement: osascript waits for the temp exec it judges

The `osascript_network_exec` rule SHALL resolve the process record of the temp exec it evaluates before walking to an osascript ancestor, and SHALL treat a missing record as every process-resolving rule does: inside the materialization grace the evaluation SHALL fail with the retryable not-yet-materialized error so the batch is re-evaluated, and past it the rule SHALL count the abandon against itself. Its ancestors SHALL still be looked up without a retry, since a parent may predate the capture and never materialize.

#### Scenario: A young temp exec is retried, then decided

- **GIVEN** an osascript chain with a download and a temp exec, whose temp exec's record has not materialized and whose event is inside the grace
- **WHEN** the rule evaluates the temp exec
- **THEN** the evaluation fails with the retryable not-yet-materialized error
- **AND** once the record materializes, the same event produces the finding

#### Scenario: A temp exec whose record never arrives is counted

- **GIVEN** a temp exec whose record is still missing once the grace has passed
- **WHEN** the rule evaluates it
- **THEN** no finding is produced and one abandon is recorded against the rule
