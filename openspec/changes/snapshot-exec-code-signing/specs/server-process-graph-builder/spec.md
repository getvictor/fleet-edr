## ADDED Requirements

### Requirement: A later snapshot completes a missing signature

When a snapshot `exec` carrying a code signature arrives for a process whose open row has no signature and the same executable path, the system SHALL record that signature on the existing row and SHALL change nothing else about it. Rows an earlier extension's snapshot created carry no signature, and a snapshot `exec` for a process that already has a row is otherwise dropped, so without this the process would stay unsigned until it exits, even after an extension that reads signatures has started.

The system SHALL NOT replace a signature a row already has, and SHALL NOT apply a snapshot's signature to a row whose path differs, since a different path is a different program.

#### Scenario: An unsigned snapshot row gains its signature

- **GIVEN** an open process row created by a snapshot `exec` with no signature
- **WHEN** a later snapshot `exec` with a signature arrives for the same pid and path
- **THEN** the same row carries that signature

#### Scenario: A row's existing signature is kept

- **GIVEN** an open process row that already carries a signature, from a live `exec` or an earlier signed snapshot
- **WHEN** a later snapshot `exec` with a different signature arrives for the same pid and path
- **THEN** the row keeps its existing signature

#### Scenario: A snapshot of a different program is not applied

- **GIVEN** an open process row with no signature
- **WHEN** a later snapshot `exec` with a signature arrives for the same pid but a different path
- **THEN** the row stays without a signature
