# Server detection rules engine: an open event says who wrote and what the write meant delta

## ADDED Requirements

### Requirement: An open event supplies the writer and the meaning of the write

The system SHALL supply, for a file-open event, the image of the process performing the open, whether the open carried write access, and whether it carried a flag that changes the file's contents.

Write access and mutating intent SHALL be supplied as separate facts rather than combined into one. A rule may need to suppress a specific writer that opens a file write-mode without changing it, which is a test on the second fact conditioned on the writer, and a single combined field cannot express it: collapsing them either loses the suppression or applies it to every writer.

A rule that reads these fields SHALL be reported as valid Sigma requiring fields only this engine supplies. Sigma's file taxonomy models a completed creation or modification rather than an open with flags, so it has no field for the intent behind an open.

#### Scenario: A write-mode open that changes nothing is distinguished from one that does

- **GIVEN** two opens of the same watched path by the same process, one taking a write-mode lock and one truncating the file
- **WHEN** a rule reads the mutating-intent field
- **THEN** it sees them as different, though both carried write access

#### Scenario: The writing process image is available to a file rule

- **GIVEN** a file-open event
- **WHEN** a rule matches on the image of the process that opened the file
- **THEN** it sees the path of that process

### Requirement: A rule suppresses a named exception rather than branching on the writer

The system SHALL let a rule state an exception as a named set of field tests its condition subtracts, so that a suppression conditional on one writer is expressed in the rule file rather than in engine code.

A suppression written this way SHALL apply only to events matching every test in it. A writer other than the named one, performing the same open, SHALL still match the rule.

#### Scenario: The suppression applies only to the writer it names

- **GIVEN** a rule suppressing a write-mode open by one named process that does not change file contents
- **WHEN** a different process performs an identical open of the same path
- **THEN** the rule matches
