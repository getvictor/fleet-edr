# server-detection-rules-engine

## MODIFIED Requirements

### Requirement: Our events supply the Sigma fields a rule reads

The system SHALL map Sigma's field names onto our event payloads, so a rule written in the Sigma format can be evaluated against captured telemetry.

The system SHALL resolve a rule's logsource category to the event type whose payload supplies its fields, and SHALL decline a category for which it supplies no fields rather than accepting one it could name but not populate.

The system SHALL decode an event's payload once and reuse it for every rule evaluated against that event. Field access itself SHALL allocate nothing, because it runs for every field of every rule against every event.

The system SHALL report a field as absent when the payload does not carry it, so that a rule matching on absence behaves as its author intended.

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

## REMOVED Requirements

### Requirement: A rule suppresses a named exception rather than branching on the writer

Removed for its title, which frames a general engine capability in the terms of the one rule that used to exercise it. The capability is unchanged and re-stated below; what changed is that the shipped rule using it retired its suppression, so the requirement is no longer about writers or opens at all.

### Requirement: An open event supplies the writer and the meaning of the write

Removed because half of it no longer holds and the title says so. The meaning of an open's flags is no longer supplied as fields a rule reads: the lock-versus-modification decision moved into the supply of the target filename, and the two fields that carried it are retired. The surviving half, that a file rule can match on the writer's image, is re-stated below under a title that describes only that.

## ADDED Requirements

### Requirement: An open event supplies the writer

The system SHALL supply, for a file-open event, the image of the process performing the open, so a rule can match on who changed a watched file.

The meaning of an open's flags SHALL NOT be supplied as fields a rule reads. Whether an open carried write access and whether it carried a content-changing flag decide whether the event is reported as a modification at all, which is settled where the target filename is supplied; exposing them again would let a rule read a fact this engine computes and forfeit its portability for no gain.

#### Scenario: The writing process image is available to a file rule

- **GIVEN** a file-open event
- **WHEN** a rule matches on the image of the process that opened the file
- **THEN** it sees the path of that process

### Requirement: A rule suppresses a named exception

The system SHALL let a rule state an exception as a named set of field tests its condition subtracts, so that a suppression is expressed in the rule file rather than in engine code.

A suppression written this way SHALL apply only to events matching every test in it. An event differing in any one of those tests SHALL still match the rule.

#### Scenario: The suppression applies only to what it names

- **GIVEN** a rule whose condition subtracts a named set of field tests
- **WHEN** an event matches the rule's selection but differs from the suppression in one of its tests
- **THEN** the rule matches
