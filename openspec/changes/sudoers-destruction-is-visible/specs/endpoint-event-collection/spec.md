# Endpoint event collection

## ADDED Requirements

### Requirement: Destruction of a sensitive file is captured

The system SHALL emit a `file_truncate` event when a process discards the contents of a file in the sensitive target set, and a `file_delete` event when a process removes one, each carrying the acting process PID and the path.

Truncation SHALL be captured however it is performed. `truncate(2)` and `ftruncate(2)` are one kernel path and an `open(2)` carrying `O_TRUNC` is another, and only the second is what a shell redirect uses, so capturing either alone leaves the common case invisible.

An open that does NOT discard contents SHALL NOT be emitted. The sensitive paths are read routinely (every `sudo` invocation reads the policy), so reporting those reads would turn a destruction signal into a stream of ordinary privilege checks. The filter belongs in the extension rather than in a rule, because the cost being avoided is what reaches the wire at all.

#### Scenario: A shell redirect that empties a sensitive file is captured

- **GIVEN** the extension is running with the sensitive-path file-modification client active
- **WHEN** a process empties a file in the sensitive set by opening it with `O_TRUNC`
- **THEN** a `file_truncate` event is emitted carrying the acting process PID and the path

#### Scenario: A truncate syscall is captured the same way

- **GIVEN** the extension is running with the sensitive-path file-modification client active
- **WHEN** a process empties a file in the sensitive set with `truncate(2)`
- **THEN** a `file_truncate` event is emitted, indistinguishable from the redirect case

#### Scenario: Deleting a sensitive file is captured

- **GIVEN** the extension is running with the sensitive-path file-modification client active
- **WHEN** a process unlinks a file in the sensitive set
- **THEN** a `file_delete` event is emitted carrying the acting process PID and the path

#### Scenario: A routine read of a sensitive file is not emitted

- **GIVEN** the extension is running with the sensitive-path file-modification client active
- **WHEN** a process opens a file in the sensitive set without discarding its contents
- **THEN** no event is emitted for that open
