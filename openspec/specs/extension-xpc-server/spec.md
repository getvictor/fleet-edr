# Extension XPC Server Specification

## Purpose

The extensions expose a private XPC channel that local agents use to receive events and to push policy updates back into
the device. This channel is the trust boundary between Apple-mediated kernel-side capture (system extension and network
extension entitlements) and the userland Go agent that owns enrollment, queueing, and upload. Anything connecting to it
must prove cryptographic provenance, because a connected peer is granted both the firehose of endpoint telemetry and the
ability to mutate the active blocklist.

This capability defines who is allowed to connect, how connections behave when multiple agents are present, the
event-broadcast contract, the inbound message types the extensions accept, and what happens on disconnect. It does not
define the wire schema of events themselves — that is owned by the endpoint event collection capability.

## Requirements

### Requirement: Mach service registration

Each extension SHALL register a single Mach service that the Go agent connects to. The system extension SHALL register
its service in the team-prefixed namespace; the network extension SHALL register its service in the application-group
namespace. Both services SHALL accept multiple concurrent client connections.

#### Scenario: An agent connects to the system extension

- **GIVEN** the system extension is running
- **WHEN** an agent opens a Mach connection to the extension's registered service name
- **THEN** the connection succeeds once peer code-signing validation passes
- **AND** the agent begins receiving subsequent events on that connection

#### Scenario: Two agents connect at the same time

- **GIVEN** the system extension is running
- **WHEN** two distinct, validly-signed agent processes each open a Mach connection to the same service
- **THEN** both connections are accepted
- **AND** every event the extension produces while both are connected is delivered to both peers

### Requirement: Peer code-signing validation

The extensions SHALL reject any inbound XPC connection whose peer does not satisfy a code-signing requirement chained to
the Apple anchor and the Fleet Device Management team identifier. The validation MUST run before any event is delivered
to the peer and before any inbound message from the peer is processed.

#### Scenario: A peer with the wrong team ID is rejected

- **GIVEN** an extension's XPC service is listening
- **WHEN** a process signed with a team ID other than `FDG8Q7N4CC` attempts to connect
- **THEN** the extension cancels the connection
- **AND** the rejected peer never receives any events
- **AND** any inbound message from that peer is discarded

#### Scenario: An ad-hoc-signed peer is rejected

- **GIVEN** an extension's XPC service is listening
- **WHEN** a process without a chain to the Apple anchor attempts to connect
- **THEN** the extension cancels the connection

#### Scenario: A correctly-signed agent is accepted

- **GIVEN** an extension's XPC service is listening
- **WHEN** a process signed with the hardened runtime and team ID `FDG8Q7N4CC` connects
- **THEN** the connection is accepted
- **AND** the peer is added to the broadcast set

### Requirement: Event broadcast to all connected peers

When the extension emits an event, it SHALL deliver that event to every currently-connected, validated peer as an XPC
dictionary message containing a `data` field whose value is the raw JSON event bytes.

#### Scenario: An event is broadcast to multiple agents

- **GIVEN** two validated agent connections are open
- **WHEN** the extension emits a single event
- **THEN** each connected agent receives one XPC dictionary message
- **AND** each message carries identical `data` bytes

#### Scenario: An event is emitted with no peers connected

- **GIVEN** the extension is running and no agents are connected
- **WHEN** the extension emits an event
- **THEN** the extension does not buffer the event for future peers
- **AND** the event is silently discarded from the XPC channel

### Requirement: Inbound policy update

The system extension SHALL accept inbound XPC dictionary messages with `type = policy.update` and a `data` field
containing raw policy JSON bytes from any validated peer. On receipt the extension MUST replace the active blocklist
with the policy described by `data` and MUST persist that policy so it survives extension restart.

#### Scenario: The agent pushes a new blocklist

- **GIVEN** a validated agent connection is open to the system extension
- **WHEN** the agent sends a `policy.update` message with new blocklist JSON
- **THEN** the new blocklist becomes the active policy used by exec authorization
- **AND** the new blocklist persists across a restart of the extension

#### Scenario: A policy.update with no data is rejected

- **GIVEN** a validated agent connection is open to the system extension
- **WHEN** the agent sends a `policy.update` message with no `data` field or empty data
- **THEN** the extension does not change the active blocklist
- **AND** the extension continues serving events to all peers

### Requirement: Hello handshake support

The extensions SHALL accept an inbound XPC dictionary message with `type = hello` and treat it as a no-op. This allows
clients to trigger the lazy Mach port bind without side effects.

#### Scenario: The agent sends a hello after connecting

- **GIVEN** a validated agent connection has just been established
- **WHEN** the agent sends a message with `type = hello`
- **THEN** the extension processes the message without changing any state
- **AND** the extension continues to broadcast events normally

### Requirement: Forward compatibility for unknown messages

The extensions SHALL ignore inbound XPC dictionary messages whose `type` field is not recognized, and MUST NOT close the
peer connection in response to one. This allows agents to evolve the protocol additively without breaking older
extensions.

#### Scenario: Future agent sends a new message type

- **GIVEN** a validated agent connection is open
- **WHEN** the agent sends a message with a `type` value the extension does not recognize
- **THEN** the extension does not change any state
- **AND** the connection remains open
- **AND** events continue to be broadcast to that peer

### Requirement: Disconnect cleanup

When an XPC peer disconnects — whether because the agent process exited, the connection was interrupted, or the agent
called disconnect — the extension SHALL remove that peer from the broadcast set and SHALL stop sending events to it.
A disconnect MUST NOT affect any other connected peer.

#### Scenario: One of two agents goes away

- **GIVEN** two validated agent connections are open and receiving events
- **WHEN** one agent process exits
- **THEN** the extension removes the dead peer from the broadcast set
- **AND** the remaining agent continues to receive every subsequent event
- **AND** the extension does not crash or hang

#### Scenario: An agent reconnects after disconnect

- **GIVEN** an agent disconnected from the extension
- **WHEN** the agent re-opens a Mach connection and re-passes peer code-signing validation
- **THEN** the new connection is accepted as a fresh peer
- **AND** the new connection begins receiving events from the moment it joins
