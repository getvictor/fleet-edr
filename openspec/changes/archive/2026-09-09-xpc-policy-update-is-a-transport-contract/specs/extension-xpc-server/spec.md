# Extension XPC Server Specification

## MODIFIED Requirements

### Requirement: Inbound policy update

The system extension SHALL accept an inbound XPC dictionary message with `type = application_control.update` from a validated peer, carrying the application-control snapshot as raw JSON bytes in a `data` field, and SHALL hand those bytes to the snapshot store unread.

This requirement owns the transport only. What the snapshot means, when a delivered snapshot is accepted or rejected for recency, how it replaces the active state, and how it is persisted so it survives an extension restart are the snapshot store's contract, specified by `extension-application-control`'s snapshot requirement. Restating any of that here would be a second, shorter description of the same behaviour that drifts from it: the version in this capability described a "blocklist" long after the model became a typed rule snapshot, and never mentioned the recency gate at all.

A message whose `data` field is absent, or present and empty, SHALL be rejected without touching the active snapshot and without closing the connection, so a malformed push cannot disarm enforcement or cost the peer its event stream.

#### Scenario: The agent pushes a new snapshot

- **GIVEN** a validated agent connection is open to the system extension
- **WHEN** the agent sends an `application_control.update` message carrying snapshot JSON in `data`
- **THEN** the extension hands exactly those bytes to the snapshot store
- **AND** what happens to them from there is the snapshot store's contract, not this one

#### Scenario: An application_control.update with no data is rejected

- **GIVEN** a validated agent connection is open to the system extension
- **WHEN** the agent sends an `application_control.update` message whose `data` field is absent or empty
- **THEN** the extension rejects the message
- **AND** the active snapshot is unchanged
- **AND** the connection stays open and continues to serve events
