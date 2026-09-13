## ADDED Requirements

### Requirement: Inbound watched-path update

The system extension SHALL accept an inbound XPC dictionary message with `type = watched_paths.update` from a validated peer, carrying a watched-path set as raw JSON bytes in a `data` field, and SHALL hand those bytes to the file-tamper client's watched set unread.

As with `application_control.update`, this requirement owns only the transport. What the set means and how it is applied and persisted are specified by `endpoint-event-collection`.

A message whose `data` field is absent, or present and empty, SHALL be rejected without changing the watched set and without closing the connection.

#### Scenario: The agent pushes a watched-path set

- **GIVEN** a validated agent connection is open to the system extension
- **WHEN** the agent sends a `watched_paths.update` message carrying a set in `data`
- **THEN** the extension hands exactly those bytes to the watched set

#### Scenario: A watched_paths.update with no data is rejected

- **GIVEN** a validated agent connection is open to the system extension
- **WHEN** the agent sends a `watched_paths.update` message whose `data` field is absent or empty
- **THEN** the extension rejects the message
- **AND** the watched set is unchanged
- **AND** the connection stays open and continues to serve events
