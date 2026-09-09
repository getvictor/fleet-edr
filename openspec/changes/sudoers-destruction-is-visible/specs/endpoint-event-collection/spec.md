# Endpoint event collection

## ADDED Requirements

### Requirement: Destruction of a sensitive file is captured

The system SHALL emit a `file_truncate` event when a process discards the contents of a file in the sensitive target set, and a `file_delete` event when a process removes one, each carrying the acting process PID and the path.

Truncation SHALL be captured however it is performed. `truncate(2)` and `ftruncate(2)` are one kernel path and an `open(2)` carrying `O_TRUNC` is another, and only the second is what a shell redirect uses, so capturing either alone leaves the common case invisible.

An open that does NOT discard contents SHALL NOT be emitted. The sensitive paths are read routinely, since every `sudo` invocation reads the policy, so reporting those reads would turn a destruction signal into a stream of ordinary privilege checks. The filter belongs in the extension rather than in a rule, because what is being avoided is what reaches the wire at all.

Note on verification: the scenarios below pin the event SHAPES, which is what this repository's tests can reach. That the ESF client is subscribed to the three event types, that an `O_TRUNC` open is told from a routine read, and that a truncate syscall and a shell redirect both arrive are exercised at the system / VM layer per `docs/testing-strategy.md`, because `FileTamperSubscriber` imports EndpointSecurity and is outside the unit-testable target.

#### Scenario: An emptied file is reported as a truncation

- **GIVEN** a process has discarded the contents of a file in the sensitive set
- **WHEN** the extension serializes the event
- **THEN** a `file_truncate` event carries the acting process PID and the path
- **AND** the same shape is produced whether the contents were discarded by a truncate syscall or by an open carrying `O_TRUNC`

#### Scenario: A removed file is reported as a deletion

- **GIVEN** a process has removed a file in the sensitive set
- **WHEN** the extension serializes the event
- **THEN** a `file_delete` event carries the acting process PID and the path
- **AND** it is distinguishable from a truncation, because an emptied file still exists and a removed one does not
