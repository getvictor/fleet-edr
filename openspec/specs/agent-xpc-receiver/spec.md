# Agent XPC Receiver Specification

## Purpose

The agent's XPC receivers are the device-side ingestion edge of the Go agent. They open and maintain Mach connections
to the system extension and the network extension, surface inbound event bytes onto Go channels, and surface outbound
policy pushes back to the system extension. Because the extensions broadcast events without any acknowledgement, the
receiver is responsible for staying connected through extension restarts, transient XPC errors, and brief gaps between
the two processes' lifetimes.

This capability defines how the agent maintains those connections, how it recovers when an extension is unavailable
or restarts, and what observable guarantees and non-guarantees the rest of the agent (queue, uploader, commander) can
rely on. It does not define the wire format of events; that contract is owned by the endpoint event collection
capability.

## Requirements

### Requirement: Two parallel receiver loops

The agent SHALL run two independent receiver loops, one for the system extension's Mach service and one for the network
extension's Mach service. The two loops MUST be independent: a failure on one MUST NOT stop event ingestion on the
other.

#### Scenario: Network extension is down while system extension is up

- **GIVEN** the agent is running and connected to the system extension
- **WHEN** the network extension is not running
- **THEN** the agent continues receiving events from the system extension
- **AND** the agent continues attempting to connect to the network extension in the background

#### Scenario: System extension restarts while network extension stays up

- **GIVEN** the agent is connected to both extensions
- **WHEN** the system extension restarts
- **THEN** the agent reconnects to the system extension
- **AND** the agent's connection to the network extension is unaffected

### Requirement: Exponential reconnect backoff

When a receiver fails to establish a connection to an extension, the agent SHALL retry with exponential backoff
starting at one second and capped at thirty seconds. Once a connection is successfully established, the backoff for
that receiver MUST reset so the next disconnect retries quickly.

#### Scenario: Repeated connection failures back off

- **GIVEN** the agent has just started and the system extension is not yet listening
- **WHEN** the receiver fails to connect repeatedly
- **THEN** the gap between attempts grows from one second toward a thirty-second cap
- **AND** the agent does not busy-loop against the missing peer

#### Scenario: Backoff resets after a successful connection

- **GIVEN** the receiver has been backing off after several failed connection attempts
- **WHEN** the next attempt succeeds and a session begins
- **THEN** the backoff resets to its initial value
- **AND** if that session later disconnects the next reconnect attempt happens promptly

### Requirement: Auto-reconnect after extension restart

When an XPC connection is interrupted, invalidated, or terminated, the receiver SHALL tear down the dead connection and
attempt to reconnect. The receiver MUST treat all of these XPC error conditions as triggers to reconnect.

#### Scenario: Extension is killed and respawned

- **GIVEN** the agent is connected to an extension and receiving events
- **WHEN** the extension process is killed and respawned by the operating system
- **THEN** the agent observes the connection error
- **AND** the agent reconnects to the extension once it is listening again
- **AND** event delivery resumes

### Requirement: Dropped events during disconnect are tolerated

The agent SHALL accept that any events emitted by an extension during the gap between disconnect and reconnect are not
delivered to the agent. The agent MUST NOT crash, deadlock, or stop processing on the basis of missed events; it MUST
continue with whatever events the extension delivers after reconnection.

#### Scenario: Events occur during a reconnect window

- **GIVEN** the agent is briefly disconnected from an extension
- **WHEN** the extension emits events while the agent is disconnected
- **THEN** the agent does not see those events
- **AND** when the agent reconnects it begins processing subsequent events normally

### Requirement: Outbound policy push routed to active connection

The agent SHALL provide a mechanism for sending policy updates to the system extension over the same XPC connection.
A policy push MUST succeed only when an active connection to the system extension is available; if no connection is
available the push MUST fail with an error so the caller can retry once the connection is re-established.

#### Scenario: Policy push during an active connection

- **GIVEN** the agent has an active XPC connection to the system extension
- **WHEN** the agent attempts to push a policy update
- **THEN** the push is delivered to the system extension over that connection
- **AND** the call returns success once the message has been handed to XPC

#### Scenario: Policy push while disconnected

- **GIVEN** the agent has no active connection to the system extension
- **WHEN** the agent attempts to push a policy update
- **THEN** the push fails with an error
- **AND** the caller is responsible for retrying once a connection is re-established

### Requirement: Events flow into the queue without blocking the receiver

The receiver SHALL deliver received events into a downstream channel without blocking on the channel. If the downstream
buffer is full the receiver MAY drop the affected event but MUST emit a warning so operators can detect the
condition. The receiver MUST keep reading subsequent events from the XPC connection.

#### Scenario: Downstream consumer falls behind

- **GIVEN** the receiver is delivering events into a buffered channel
- **WHEN** the consumer is too slow and the channel fills up
- **THEN** the receiver drops the event that could not be enqueued
- **AND** the receiver logs a warning identifying the affected service
- **AND** the receiver continues reading subsequent events

### Requirement: Clean shutdown on context cancellation

When the agent's operating context is cancelled (for example, on SIGTERM), the receiver loops SHALL exit and close their
XPC connections. No further reconnection attempts MUST be made after cancellation.

#### Scenario: Agent receives SIGTERM

- **GIVEN** the agent is running with both receiver loops active
- **WHEN** the agent process is sent SIGTERM
- **THEN** both receiver loops stop attempting to reconnect
- **AND** both receiver loops disconnect their XPC connections
- **AND** the agent shutdown proceeds without being blocked by the receivers
