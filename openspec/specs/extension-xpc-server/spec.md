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

#### Scenario: An ad-hoc-signed peer is rejected in production builds

- **GIVEN** a release-configured extension's XPC service is listening
- **WHEN** a process without a chain to the Apple anchor attempts to connect
- **THEN** the extension cancels the connection

#### Scenario: An ad-hoc-signed peer is accepted in debug builds when its code-directory hash matches the pinned value

- **GIVEN** a debug-configured extension's XPC service is listening, built with a pinned ad-hoc peer code-directory hash for
  local-iteration use on a SIP-disabled developer VM
- **WHEN** a process signed ad-hoc with that exact code-directory hash attempts to connect
- **THEN** the connection is accepted
- **AND** the peer is added to the broadcast set
- **AND** this code path is excluded from release builds, so a different ad-hoc-signed process cannot impersonate the agent
  in production

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
- **THEN** the extension buffers the event for delivery to the next peer that completes the hello handshake
- **AND** the buffer is bounded; once full, the oldest buffered events are dropped to make room for new ones so a permanently
  absent agent cannot exhaust extension memory

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

### Requirement: Hello handshake and reply

The extensions SHALL accept an inbound XPC dictionary message with `type = hello`. On receipt the extension MUST reply
with an outbound XPC dictionary message with `type = hello-ack` on the same peer connection, so the client can confirm
the channel is established in both directions. The exchange exists because the underlying Mach port lookup is one-way
silent on failure: without a reply, a client cannot distinguish a real listener from a stale port binding.

On receipt of `hello` the extension MUST also flush any events buffered while no peer was connected to the peer that
sent the hello, and only to that peer. This binds the buffer to a client that has demonstrated a working bidirectional
channel rather than to any peer that merely passed code-signing validation, which guards against transient phantom-peer
connections that immediately fail.

#### Scenario: The agent sends a hello after connecting

- **GIVEN** a validated agent connection has just been established and the buffer of events accumulated while no peer was
  connected is non-empty
- **WHEN** the agent sends a message with `type = hello`
- **THEN** the extension sends back a `hello-ack` message on the same peer connection
- **AND** the extension delivers every buffered event to the agent in the order it was emitted
- **AND** the buffer is cleared

#### Scenario: A peer connects and disconnects without ever sending hello

- **GIVEN** a transient peer connection that completes code-signing validation but disconnects before sending any inbound
  message
- **WHEN** the connection terminates
- **THEN** no buffered events are delivered to that peer
- **AND** the buffer remains intact for the next peer that completes the hello exchange

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

The extension SHALL remove a peer from the broadcast set and stop sending events to it whenever its XPC connection
ends, whether because the agent process exited, the connection was interrupted, or the agent called disconnect. A
disconnect MUST NOT affect any other connected peer.

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
