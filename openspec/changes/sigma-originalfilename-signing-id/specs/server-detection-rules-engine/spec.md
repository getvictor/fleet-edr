## MODIFIED Requirements

### Requirement: Our events supply the Sigma fields a rule reads

The system SHALL map Sigma's field names onto our event payloads, so a rule written in the Sigma format can be evaluated against captured telemetry.

The system SHALL resolve a rule's logsource category to the event type whose payload supplies its fields, and SHALL decline a category for which it supplies no fields rather than accepting one it could name but not populate.

The system SHALL decode an event's payload once and reuse it for every rule evaluated against that event. Field access itself SHALL allocate nothing, because it runs for every field of every rule against every event.

The system SHALL report a field as absent when the payload does not carry it, so that a rule matching on absence behaves as its author intended.

The system SHALL supply a process-creation rule's original file name from the acting process's code-signing identifier. Sigma's `OriginalFileName` is the name a binary was compiled as, which does not change when the file is renamed, and a rule reading it is detecting a tool renamed to hide it. macOS carries that property in the code signature rather than in version info: the signing identifier is embedded in the signature and cannot be changed without invalidating it.

A process carrying no signing identity SHALL supply the field as ABSENT rather than as an empty value, which is the general absence rule above applied to this field. The difference is observable: Sigma's `Field: null` matches a field the event does not carry, and `Field: ""` matches one that is present and empty. Supplying an empty value for an unsigned process would make the first fail and the second match, so the field would misreport what it knows in both directions.

The system SHALL supply a file-event rule's target filename only for an open that carries write access AND a flag that changes the file's contents. The Sigma category names file creation and modification rather than any access, so an open that only reads, and an open that only takes a write-mode lock, are both routine background activity rather than modifications. Supplying either would present known noise to every such rule as a detection.

Deciding this where the field is supplied, rather than in each rule, is what lets a file rule read only fields from Sigma's own taxonomy.

#### Scenario: Our events supply the Sigma fields a rule reads

- **GIVEN** a rule whose fields are all mapped for its event type
- **WHEN** an event of that type is evaluated
- **THEN** the rule sees the values its payload carries

#### Scenario: A read-only open supplies no target filename

- **GIVEN** a file-open event that opens a path for reading only
- **WHEN** a file-event rule is evaluated against it
- **THEN** the rule sees no target filename, and does not match

#### Scenario: A lock supplies no target filename

- **GIVEN** a file-open event that carries write access and no flag that changes the file's contents
- **WHEN** a file-event rule is evaluated against it
- **THEN** the rule sees no target filename, and does not match, because taking a lock is not a modification

#### Scenario: A rule is inert against an event type it does not name

- **GIVEN** a rule whose logsource names one event type
- **WHEN** it is evaluated against an event of a different type
- **THEN** it does not match, rather than matching on a field that happens to share a name

#### Scenario: A renamed signed binary is matched by its signing identity

- **GIVEN** a process-creation rule reading `OriginalFileName`
- **AND** a signed binary whose file has been renamed on disk
- **WHEN** the rule is evaluated against its exec event
- **THEN** the rule sees the code-signing identifier, which the rename did not change

#### Scenario: An unsigned process supplies no original file name

- **GIVEN** the same rule
- **AND** an exec event for a process carrying no code-signing identity
- **WHEN** the rule is evaluated
- **THEN** the field is absent rather than empty, so a substring or prefix test does not match it
