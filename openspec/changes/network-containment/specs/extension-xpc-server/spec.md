## ADDED Requirements

### Requirement: Inbound network containment update

The network extension SHALL accept an inbound XPC dictionary message with `type = network_containment.update` from a validated peer, carrying a containment document as raw JSON bytes in a `data` field, and SHALL hand those bytes to its containment state unread.

As with `application_control.update`, this requirement owns only the transport. What the document means and how it is persisted and applied are specified by `extension-network-response`.

A message whose `data` field is absent, or present and empty, SHALL be rejected without changing the containment state and without closing the connection.

#### Scenario: The agent pushes a containment update

- **GIVEN** a validated agent connection is open to the network extension
- **WHEN** the agent sends a `network_containment.update` message carrying a document in `data`
- **THEN** the extension hands exactly those bytes to its containment state

#### Scenario: A network_containment.update with no data is rejected

- **GIVEN** a validated agent connection is open to the network extension
- **WHEN** the agent sends a `network_containment.update` message whose `data` field is absent or empty
- **THEN** the extension rejects the message
- **AND** the containment state is unchanged
- **AND** the connection stays open and continues to serve events
